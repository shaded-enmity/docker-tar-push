package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/docker/distribution"
	"github.com/docker/distribution/digest"
	versioned "github.com/docker/distribution/manifest"
	manifest "github.com/docker/distribution/manifest/schema1"
	"github.com/docker/distribution/registry/client"
	"github.com/docker/distribution/registry/client/transport"
	"github.com/docker/docker/image"
	flag "github.com/docker/docker/pkg/mflag"
	trust "github.com/docker/libtrust"

	"golang.org/x/net/context"
)

var (
	verbose, help bool
	target, key   string
	ManifestType  = "application/vnd.docker.container.image.v1+json"
	LayerType     = "application/vnd.docker.container.image.rootfs.diff+x-tar"
)

type Layer struct {
	Id, Parent string
	BlobSum    digest.Digest
	Data       string
}

type LayerMap map[string]*Layer

func init() {
	flag.BoolVar(&help, []string{"h", "-help"}, false, "Display help")
	flag.BoolVar(&verbose, []string{"v", "-verbose"}, false, "Switch to verbose output")
	flag.StringVar(&key, []string{"k", "-key-file"}, "", "Private key with which to sign")
	flag.Parse()
}

func blobSumLayer(r *tar.Reader) (digest.Digest, error) {
	sha := digest.Canonical.New()
	if _, err := io.Copy(sha.Hash(), r); err != nil {
		return "", err
	}
	return sha.Digest(), nil
}

func getLayerPrefix(s string) string {
	_, b := path.Split(path.Dir(s))
	return path.Clean(b)
}

func getLayerInfo(b []byte) (string, string, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return "", "", err
	}
	if raw["parent"] == nil {
		return "", raw["id"].(string), nil
	}
	return raw["parent"].(string), raw["id"].(string), nil
}

func getLayersFromMap(lm LayerMap) []*Layer {
	out := make([]*Layer, 0, len(lm))
	for _, v := range lm {
		out = append(out, v)
	}
	return out
}

func findChild(id string, layers []*Layer) *Layer {
	for _, l := range layers {
		if l.Parent == id {
			return l
		}
	}
	return nil
}

func getLayersInOrder(layers []*Layer) []*Layer {
	root := findChild("", layers)

	if root == nil {
		panic(errors.New("Unable to find root layer"))
	}

	out := make([]*Layer, 0, len(layers))
	out = append(out, root)
	for {
		root = findChild(root.Id, layers)
		if root == nil {
			break
		}
		out = append(out, root)
	}

	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}

	return out
}

func getRepoInfo(ri map[string]interface{}) (string, string) {
	var (
		repo string
		tag  string
	)

	for k, v := range ri {
		repo = k
		for vv, _ := range v.(map[string]interface{}) {
			tag = vv
		}
	}

	return repo, tag
}

func splitUrlAndRepo(s string) (string, string) {
	sp := strings.SplitN(s, "/", 2)
	if len(sp) != 2 {
		fmt.Fprintf(os.Stderr, "ERROR: Image name in wrong format: %s", s)
		return "127.0.0.1:5000", sp[0]
	}
	return sp[0], sp[1]
}

func getLayerRaw(archive *tar.Reader, k string) ([]byte, error) {
	for {
		hdr, err := archive.Next()
		if err == io.EOF {
			break
		}

		if strings.HasSuffix(hdr.Name, "layer.tar") {
			id := getLayerPrefix(hdr.Name)
			if k == id {
				buf := bytes.NewBuffer(nil)
				bwr := bufio.NewWriter(buf)
				io.Copy(bwr, archive)
				return buf.Bytes(), err
			}
		}
	}

	return nil, fmt.Errorf("No layer with id: %s\n", k)
}

func uploadBlobsToRegistry(repostr string, archive *tar.Reader, file *os.File, layers []*Layer, manifest *manifest.SignedManifest) error {
	url, repo := splitUrlAndRepo(repostr)

	tr := transport.NewTransport(http.DefaultTransport)
	repository, err := client.NewRepository(context.Background(), repo, "http://"+url, tr)

	for _, v := range layers {
		/* probe remote endpoint */
		dsc, err := repository.Blobs(context.Background()).Stat(context.Background(), v.BlobSum)

		switch err {
		case nil:
		case distribution.ErrBlobUnknown:
		default:
			return err
		}

		if err == distribution.ErrBlobUnknown {
			/* rewind after each seek */
			file.Seek(0, 0)
			bb, err := getLayerRaw(archive, v.Id)
			if err != nil {
				return err
			}

			if verbose {
				fmt.Printf("Uploading layer: %q size: %d\n", v.BlobSum, len(bb))
			}

			dsc, err := repository.Blobs(context.Background()).Put(context.Background(), LayerType, bb)
			if err != nil {
				return err
			}

			if verbose {
				fmt.Printf(" uploaded with digest: %q\n", dsc.Digest)
			}
		} else {
			if verbose {
				fmt.Printf("Already in blob store: %q\n", dsc.Digest)
			}
		}
	}

	manSvc, err := repository.Manifests(context.Background())
	if err == nil {
		return manSvc.Put(manifest)
	}

	return err
}

func processTarget(target string) (string, string, error) {
	var pkey trust.PrivateKey

	if key != "" {
		var err error
		pkey, err = trust.LoadKeyFile(key)
		if err != nil {
			return "", "", err
		}

		if verbose {
			fmt.Printf("Signing with: %s\n", pkey.KeyID())
		}
	}

	var f *os.File
	if target != "-" {
		var err error
		f, err = os.Open(target)
		if err != nil {
			return "", "", err
		}
		defer func() {
			if err := f.Close(); err != nil {
				panic(err)
			}
		}()
	} else {
		f = os.Stdin
	}

	var (
		repo, tag, url string
	)
	layers := LayerMap{}

	t := tar.NewReader(bufio.NewReader(f))
	for {
		hdr, err := t.Next()
		if err == io.EOF {
			break
		}

		if strings.HasSuffix(hdr.Name, "layer.tar") {
			id := getLayerPrefix(hdr.Name)
			sum, _ := blobSumLayer(t)
			if _, ok := layers[id]; !ok {
				layers[id] = &Layer{Id: id}
			} else {
				layers[id].BlobSum = sum
			}
		}

		if strings.HasSuffix(hdr.Name, "json") {
			data, _ := ioutil.ReadAll(t)
			parent, id, _ := getLayerInfo(data)
			if _, ok := layers[id]; !ok {
				layers[id] = &Layer{Id: id, Parent: parent}
			} else {
				layers[id].Parent = parent
			}

			var img image.Image
			json.Unmarshal(data, &img)
			b, _ := json.Marshal(img)
			layers[id].Data = string(b) + "\n"
		}

		if hdr.Name == "repositories" {
			r, _ := ioutil.ReadAll(t)
			var raw map[string]interface{}
			if err := json.Unmarshal(r, &raw); err != nil {
				return "", "", err
			}

			repo, tag = getRepoInfo(raw)
			if !strings.Contains(repo, "/") {
				repo = "docker.io/" + repo
			}
		}
	}

	if strings.Count(repo, "/") > 1 {
		_, url = splitUrlAndRepo(repo)
	} else {
		url = repo
	}

	m := manifest.Manifest{
		Versioned: versioned.Versioned{
			SchemaVersion: 1,
		},
		Name: url, Tag: tag, Architecture: "amd64"}

	ll := getLayersInOrder(getLayersFromMap(layers))
	for _, l := range ll {
		m.FSLayers = append(m.FSLayers, manifest.FSLayer{BlobSum: l.BlobSum})
		m.History = append(m.History, manifest.History{V1Compatibility: l.Data})
	}

	dgstr := digest.Canonical.New()
	x, err := json.MarshalIndent(m, "", "   ")
	dgstr.Hash().Write(x)
	dgst := dgstr.Digest().String()

	if pkey != nil {
		sm, err := manifest.Sign(&m, pkey)

		/* rewind the archive */
		f.Seek(0, 0)
		t = tar.NewReader(bufio.NewReader(f))

		err = uploadBlobsToRegistry(repo, t, f, ll, sm)
		if err != nil {
			return "", "", err
		}
		x, err = sm.MarshalJSON()
		return dgst, string(x), err
	} else {
		x, err = json.MarshalIndent(m, "", "   ")
		return dgst, string(x), err
	}
}

func main() {
	if help {
		flag.PrintDefaults()
	} else {
		target := flag.Arg(0)
		if key == "" {
			fmt.Fprintln(os.Stderr, "WARNING: No signing key specified, upload *DISABLED*")
		}

		if target != "" {
			digest, manifest, err := processTarget(target)
			if err != nil {
				fmt.Printf("Error processing target: %s\n", err)
				os.Exit(1)
			}

			if verbose {
				fmt.Println(manifest)
			}
			fmt.Printf("Done! Referencing digest: %s\n", digest)
		}
	}

	os.Exit(0)
}
