# tw (tee-dub)
tw (pronounced tee-dub) is a centralized repository for testing and building
tools or helpers.

## Release to Wolfi
To release a version of tw to wolfi, run tools/release-to-wolfi.

    $ git tag vX.Y.Z
    $ git push origin vX.Y.Z
    $ ./tools/release-to-wolfi vX.Y.Z ~/src/wolfi-os/

This takes care of updating the `tw.yaml` file from `melange.yaml`
here, and copying pipeline updates over.

That will do a commit and you just need to push and do a PR.
