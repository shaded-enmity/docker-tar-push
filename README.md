# docker-tar-push
Tool that takes a Tar archive as produced by 'docker save' and uploads it to a V2 registry

## Get / Build

```bash
$ git clone https://github.com/shaded-enmity/docker-tar-push
$ cd docker-tar-push/

# build docker-tar-push itself
$ go build

# build genkey
$ cd genkey/
$ go build
```

## Example usage

Generating a _private key_ for signing (defaulting to `ECDSA/256`):
```bash
$ genkey/genkey > secret.json
```

Pushing image:
```bash
# retag poiting to a local V2 registry
$ docker tag busybox:latest 127.0.0.1:5000/library/busybox:latest
$ docker save -o busybox.tar 127.0.0.1:5000/library/busybox:latest
$ docker-tar-push -k secret.json busybox.tar
Done! Referencing digest: sha256:84f1ac57c826706a1a9dcd486aaa161ecaa48295f46e71dd400d58ad9ce0d341
```

