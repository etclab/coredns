### Running CoreDNS in Ego
- ego only supports upto Go v1.23.5, so using the [v1.12.3 tag](https://github.com/coredns/coredns/releases/tag/v1.12.3) of coredns.

### Steps for testing CoreDNS with Ego
```bash
# install ego,ego-go if not already with: 
./dev/s/install-ego.sh

# build, and sign coredns with Ego
make ego

# run coredns with Ego (starts coredns at 1053)
make ego-run

# cc: https://coredns.io/manual/toc/#testing
# test using dig (in a new terminal)
dig @localhost -p 1053 a whoami.example.org
```

### References
- [CoreDNS Source Install](https://github.com/coredns/coredns#compilation-from-source)
- [Ego Docs](https://ego-docs.netlify.app/ego)