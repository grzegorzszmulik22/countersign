// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package fakereg

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/countersign/countersign/test/fixtures/fxlib"
)

// epoch is the fixed timestamp inside every generated artifact so builds (and
// therefore the state digest) are byte-deterministic across __reset.
var epoch = time.Unix(1700000000, 0)

// normalize applies PEP 503 name normalization.
func normalize(name string) string {
	return strings.NewReplacer("-", "-", "_", "-", ".", "-").Replace(strings.ToLower(name))
}

// recordLine is a wheel RECORD line: name,sha256=<urlsafe b64 no pad>,<len>.
func recordLine(name string, data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%s,sha256=%s,%d\n", name, base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h[:]), len(data))
}

// buildWheel produces a minimal valid py3-none-any wheel.
func buildWheel(name, version string, files map[string]string) []byte {
	di := fmt.Sprintf("%s-%s.dist-info", strings.ReplaceAll(name, "-", "_"), version)
	all := map[string][]byte{}
	for n, c := range files {
		all[n] = []byte(c)
	}
	all[di+"/METADATA"] = []byte(fmt.Sprintf("Metadata-Version: 2.1\nName: %s\nVersion: %s\n", name, version))
	all[di+"/WHEEL"] = []byte("Wheel-Version: 1.0\nGenerator: fakereg\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)
	var rec strings.Builder
	for _, n := range names {
		rec.WriteString(recordLine(n, all[n]))
	}
	rec.WriteString(di + "/RECORD,,\n")
	all[di+"/RECORD"] = []byte(rec.String())
	names = append(names, di+"/RECORD")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		w, _ := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Deflate, Modified: epoch})
		_, _ = w.Write(all[n])
	}
	_ = zw.Close()
	return buf.Bytes()
}

// buildSdist produces a .tar.gz sdist whose pyproject.toml points at the
// in-tree PEP 517 backend (backend.py) — the "install script" of the spec.
// Building the wheel runs the embedded command inside the installing
// environment; needs no setuptools or network (requires = []).
func buildSdist(name, version, command string) []byte {
	dir := fmt.Sprintf("%s-%s/", name, version)
	backend := fmt.Sprintf(`import base64, hashlib, os, zipfile

CMD = %q

def _run():
    os.system(CMD)

def _record(zf_name, data):
    h = hashlib.sha256(data).digest()
    return "%%s,sha256=%%s,%%d\n" %% (
        zf_name, base64.urlsafe_b64encode(h).rstrip(b"=").decode(), len(data))

def get_requires_for_build_wheel(config_settings=None):
    return []

def get_requires_for_build_sdist(config_settings=None):
    return []

def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    _run()
    di = "%s-%s.dist-info"
    os.makedirs(os.path.join(metadata_directory, di), exist_ok=True)
    with open(os.path.join(metadata_directory, di, "METADATA"), "w") as f:
        f.write("Metadata-Version: 2.1\nName: %s\nVersion: %s\n")
    with open(os.path.join(metadata_directory, di, "WHEEL"), "w") as f:
        f.write("Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
    return di

def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _run()
    di = "%s-%s.dist-info"
    whl_name = "%s-%s-py3-none-any.whl"
    files = {
        "%s/__init__.py": b"MARKER='installed'\n",
        di + "/METADATA": b"Metadata-Version: 2.1\nName: %s\nVersion: %s\n",
        di + "/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    rec = "".join(_record(n, d) for n, d in files.items()) + di + "/RECORD,,\n"
    files[di + "/RECORD"] = rec.encode()
    with zipfile.ZipFile(os.path.join(wheel_directory, whl_name), "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in files.items():
            z.writestr(n, d)
    return whl_name
`, command, name, version, name, version, name, version, name, version, name, name, version)

	files := map[string]string{
		dir + "pyproject.toml": "[build-system]\nrequires = []\nbuild-backend = \"backend\"\nbackend-path = [\".\"]\n\n[project]\nname = \"" + name + "\"\nversion = \"" + version + "\"\n",
		dir + "backend.py":     backend,
		dir + "PKG-INFO":       fmt.Sprintf("Metadata-Version: 2.1\nName: %s\nVersion: %s\n", name, version),
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.ModTime = epoch
	tw := tar.NewWriter(gw)
	for _, n := range names {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), ModTime: epoch})
		_, _ = tw.Write([]byte(files[n]))
	}
	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}

func cleanWheel(name, version string) *Pkg {
	mod := strings.ReplaceAll(name, "-", "_")
	whl := buildWheel(name, version, map[string]string{
		mod + "/__init__.py": fmt.Sprintf("\"\"\"Fixture package %s.\"\"\"\n__version__ = %q\nMARKER = 'clean'\n", name, version),
	})
	tgz, sha1 := buildNpmTarball(name, version, nil)
	return &Pkg{
		Name: name, Version: version, Kind: "wheel",
		PyFile:  fmt.Sprintf("%s-%s-py3-none-any.whl", strings.ReplaceAll(name, "-", "_"), version),
		PyBytes: whl, PySHA: fxlib.DigestBytes(whl),
		NpmBytes: tgz, NpmSHA: sha1,
	}
}

// evilPackage builds the evilpkg artifacts: a sdist-only PyPI package whose
// in-tree backend runs command at install, and an npm tarball with the
// command as postinstall.
func evilPackage(name, version, command string) *Pkg {
	if command == "" {
		command = "echo evilpkg-default > /tmp/evilpkg-ran"
	}
	sd := buildSdist(name, version, command)
	tgz, sha1 := buildNpmTarball(name, version, map[string]string{"postinstall": command})
	return &Pkg{
		Name: name, Version: version, Kind: "sdist",
		PyFile:  fmt.Sprintf("%s-%s.tar.gz", name, version),
		PyBytes: sd, PySHA: fxlib.DigestBytes(sd),
		NpmBytes: tgz, NpmSHA: sha1,
		Scripts: map[string]string{"postinstall": command},
	}
}

// --- PyPI simple index + files ------------------------------------------------

func (s *Server) pypi(w http.ResponseWriter, r *http.Request) {
	_, _ = s.Obs.AddHTTP(r, "https", map[string]any{"rest": "pypi"})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	p := strings.TrimSuffix(r.URL.Path, "/")
	if p == "/simple" {
		s.mu.Lock()
		var b strings.Builder
		b.WriteString("<!DOCTYPE html>\n<html><head><title>Simple index</title></head><body>\n")
		for name := range s.pkgs {
			fmt.Fprintf(&b, "<a href=\"/simple/%s/\">%s</a><br/>\n", name, name)
		}
		s.mu.Unlock()
		b.WriteString("</body></html>\n")
		_, _ = w.Write([]byte(b.String()))
		return
	}
	name := normalize(strings.TrimPrefix(p, "/simple/"))
	s.mu.Lock()
	pkg, ok := s.pkgs[name]
	s.mu.Unlock()
	if !ok {
		fxlib.WriteJSON(w, 404, map[string]string{"error": "no such package"})
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<!DOCTYPE html>\n<html><head><title>Links for %s</title></head><body>\n<h1>Links for %s</h1>\n", pkg.Name, pkg.Name)
	fmt.Fprintf(&b, "<a href=\"/packages/%s#sha256=%s\" data-requires-python=\"&gt;=3.8\">%s</a><br/>\n",
		pkg.PyFile, strings.TrimPrefix(pkg.PySHA, "sha256:"), pkg.PyFile)
	b.WriteString("</body></html>\n")
	_, _ = w.Write([]byte(b.String()))
}

func (s *Server) pypiFile(w http.ResponseWriter, r *http.Request) {
	fn := strings.TrimPrefix(r.URL.Path, "/packages/")
	_, _ = s.Obs.AddHTTP(r, "https", map[string]any{"rest": "pypi-file", "file": fn})
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.pkgs {
		if p.PyFile == fn {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(p.PyBytes)
			return
		}
	}
	fxlib.WriteJSON(w, 404, map[string]string{"error": "no such file"})
}
