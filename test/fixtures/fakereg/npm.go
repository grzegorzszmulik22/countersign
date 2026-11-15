// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package fakereg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/countersign/countersign/test/fixtures/fxlib"
)

// buildNpmTarball returns a package .tgz (files under package/) and its sha1
// (npm's legacy dist.shasum field).
func buildNpmTarball(name, version string, scripts map[string]string) ([]byte, string) {
	pj := map[string]any{"name": name, "version": version, "main": "index.js"}
	if len(scripts) > 0 {
		pj["scripts"] = scripts
	}
	pjb, _ := json.MarshalIndent(pj, "", "  ")
	files := map[string][]byte{
		"package/package.json": pjb,
		"package/index.js":     []byte("module.exports = { name: " + jsonString(name) + " };\n"),
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
		c := files[n]
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c)), ModTime: epoch})
		_, _ = tw.Write(c)
	}
	_ = tw.Close()
	_ = gw.Close()
	h := sha1.Sum(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(h[:])
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// --- npm registry -------------------------------------------------------------

// npm serves GET /<pkg> metadata and GET /<pkg>/-/<file>.tgz tarballs.
func (s *Server) npm(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimSuffix(r.URL.Path, "/")
	if i := strings.Index(p, "/-/"); i > 0 {
		s.npmTarball(w, r, p[1:i], p[i+3:])
		return
	}
	name := normalize(strings.TrimPrefix(p, "/"))
	if name == "" {
		fxlib.WriteJSON(w, 404, map[string]string{"error": "not found"})
		return
	}
	_, _ = s.Obs.AddHTTP(r, "https", map[string]any{"rest": "npm-meta", "pkg": name})
	s.mu.Lock()
	pkg, ok := s.pkgs[name]
	s.mu.Unlock()
	if !ok {
		fxlib.WriteJSON(w, 404, map[string]string{"error": "no such package"})
		return
	}
	tarball := fmt.Sprintf("https://%s/%s/-/%s-%s.tgz", r.Host, pkg.Name, pkg.Name, pkg.Version)
	ver := map[string]any{
		"name": pkg.Name, "version": pkg.Version,
		"dist": map[string]any{"tarball": tarball, "shasum": pkg.NpmSHA},
	}
	if len(pkg.Scripts) > 0 {
		ver["scripts"] = pkg.Scripts
	}
	doc := map[string]any{
		"name":           pkg.Name,
		"dist-tags":      map[string]any{"latest": pkg.Version},
		"versions":       map[string]any{pkg.Version: ver},
		"time":           map[string]any{pkg.Version: "2026-01-01T00:00:00.000Z", "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z"},
		"_rev":           "1-0",
		"description":    "fixture package",
		"license":        "Apache-2.0",
		"repository":     map[string]any{"type": "git", "url": "https://github.com/acme/widgets.git"},
		"maintainers":    []any{},
		"author":         map[string]string{"name": "fixtures"},
		"readmeFilename": "",
	}
	fxlib.WriteJSON(w, 200, doc)
}

func (s *Server) npmTarball(w http.ResponseWriter, r *http.Request, name, file string) {
	_, _ = s.Obs.AddHTTP(r, "https", map[string]any{"rest": "npm-tarball", "pkg": name, "file": file})
	s.mu.Lock()
	pkg, ok := s.pkgs[normalize(name)]
	s.mu.Unlock()
	if !ok || fmt.Sprintf("%s-%s.tgz", pkg.Name, pkg.Version) != file {
		fxlib.WriteJSON(w, 404, map[string]string{"error": "no such tarball"})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(pkg.NpmBytes)
}
