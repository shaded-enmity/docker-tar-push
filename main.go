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
	"github.com/docker/docker/opts"
	flag "github.com/docker/docker/pkg/mflag"
	trust "github.com/docker/libtrust"

	"golang.org/x/net/context"
)

var (
	verbose, help bool
	target        string
	keys          = opts.NewListOpts(nil)
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
	flag.Var(&keys, []string{"k", "-key-file"}, "Private key with which to sign")
	flag.Parse()
	if kk := flag.Lookup("-k"); kk != nil {
		keys = *kk.Value.(*opts.ListOpts)
	}
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
				_, err := io.Copy(bwr, archive)
				return buf.Bytes(), err
			}
		}
	}

	return nil, fmt.Errorf("No layer with id: %s\n", k)
}

func uploadBlobsToRegistry(repostr string, file *os.File, layers []*Layer, manifest *manifest.SignedManifest) error {
	/* rewind first */
	file.Seek(0, 0)
	archive := tar.NewReader(bufio.NewReader(file))

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

func getKeys(keys []string) ([]trust.PrivateKey, error) {
	var pkeys []trust.PrivateKey

	if len(keys) != 0 {
		for _, k := range keys {
			pkey, err := trust.LoadKeyFile(k)
			if err != nil {
				return nil, err
			}

			if verbose {
				fmt.Printf("Signing with: %s\n", pkey.KeyID())
			}

			pkeys = append(pkeys, pkey)
		}
	}

	return pkeys, nil
}

func getFileFromTarget(target string) (*os.File, error) {
	var f *os.File
	if target != "-" {
		var err error
		f, err = os.Open(target)
		if err != nil {
			return nil, err
		}
	} else {
		f = os.Stdin
	}

	return f, nil
}

func createManifest(name string, tag string, arch string, ordered []*Layer) (*manifest.Manifest, []byte, digest.Digest, error) {
	var m *manifest.Manifest
	m = &manifest.Manifest{
		Versioned: versioned.Versioned{
			SchemaVersion: 1,
		},
		Name: name, Tag: tag, Architecture: arch}

	for _, l := range ordered {
		m.FSLayers = append(m.FSLayers, manifest.FSLayer{BlobSum: l.BlobSum})
		m.History = append(m.History, manifest.History{V1Compatibility: l.Data})
	}

	dgstr := digest.Canonical.New()
	data, err := json.MarshalIndent(m, "", "   ")
	if err != nil {
		return nil, nil, "", err
	}

	dgstr.Hash().Write(data)

	return m, data, dgstr.Digest(), nil
}

func createSignedManifest(raw []byte, m *manifest.Manifest, keys []trust.PrivateKey) (*manifest.SignedManifest, error) {
	var sigs []*trust.JSONSignature

	for _, k := range keys {
		js, err := trust.NewJSONSignature(raw)
		if err != nil {
			return nil, err
		}
		if err := js.Sign(k); err != nil {
			return nil, err
		}
		sigs = append(sigs, js)
	}

	sg := sigs[0]
	if err := sg.Merge(sigs[1:]...); err != nil {
		return nil, err
	}

	bts, err := sg.PrettySignature("signatures")
	if err != nil {
		return nil, err
	}

	sm := &manifest.SignedManifest{Manifest: *m, Raw: bts}

	return sm, nil
}

func processTarget(target string, keys []string) (string, string, error) {
	var (
		repo, tag, name string
		data            []byte
		err             error
		f               *os.File
		pkeys           []trust.PrivateKey
		layers          = LayerMap{}
	)

	pkeys, err = getKeys(keys)
	if err != nil {
		return "", "", err
	}

	f, err = getFileFromTarget(target)
	if err != nil {
		return "", "", err
	}
	defer func() {
		if err := f.Close(); err != nil {
			panic(err)
		}
	}()

	t := tar.NewReader(bufio.NewReader(f))
	for {
		hdr, err := t.Next()
		if err == io.EOF {
			break
		}

		if strings.HasSuffix(hdr.Name, "layer.tar") {
			id := getLayerPrefix(hdr.Name)
			sum, err := blobSumLayer(t)
			if err != nil {
				return "", "", err
			}

			if _, ok := layers[id]; !ok {
				layers[id] = &Layer{Id: id}
			} else {
				layers[id].BlobSum = sum
			}
		}

		if strings.HasSuffix(hdr.Name, "json") {
			data, err := ioutil.ReadAll(t)
			if err != nil {
				return "", "", err
			}

			parent, id, err := getLayerInfo(data)
			if err != nil {
				return "", "", err
			}

			if _, ok := layers[id]; !ok {
				layers[id] = &Layer{Id: id, Parent: parent}
			} else {
				layers[id].Parent = parent
			}

			var img image.Image
			if err := json.Unmarshal(data, &img); err != nil {
				return "", "", nil
			}

			b, err := json.Marshal(img)
			if err != nil {
				return "", "", nil
			}

			layers[id].Data = string(b) + "\n"
		}

		if hdr.Name == "repositories" {
			var raw map[string]interface{}
			r, err := ioutil.ReadAll(t)
			if err != nil {
				return "", "", err
			}

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
		_, name = splitUrlAndRepo(repo)
	} else {
		name = repo
	}

	ordered := getLayersInOrder(getLayersFromMap(layers))
	m, bytes, dgst, err := createManifest(name, tag, "amd64", ordered)
	if len(pkeys) != 0 {
		sm, err := createSignedManifest(bytes, m, pkeys)
		if err != nil {
			return "", "", err
		}

		err = uploadBlobsToRegistry(repo, f, ordered, sm)
		if err != nil {
			return "", "", err
		}

		data, err = sm.MarshalJSON()
	} else {
		data, err = json.MarshalIndent(m, "", "   ")
	}

	if err != nil {
		return "", "", err
	}

	return dgst.String(), string(data), err

}

func main() {
	if help {
		flag.PrintDefaults()
	} else {
		target := flag.Arg(0)

		if keys.Len() == 0 {
			fmt.Fprintln(os.Stderr, "WARNING: No signing keys specified, upload *DISABLED*")
		}

		if target != "" {
			strkeys := keys.GetAll()
			digest, manifest, err := processTarget(target, strkeys)
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
