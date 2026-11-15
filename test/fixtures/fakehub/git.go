// Copyright 2026 The Countersign Authors
// SPDX-License-Identifier: Apache-2.0

//go:build fixtures

package fakehub

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/countersign/countersign/test/fixtures/fxlib"
)

// Git smart HTTP through the stock `git http-backend` (02 §5: the reference
// implementation of the protocol; no reimplementation of pack handling).

// serveGitHTTP handles /{owner}/{repo}.git/... requests: known repo, mapped
// to git http-backend CGI.
func (s *Server) serveGitHTTP(w http.ResponseWriter, r *http.Request, tok string) {
	path := r.URL.Path
	i := strings.Index(path, ".git")
	repo := path[1:i] // "/{owner}/{repo}.git/..." → "{owner}/{repo}"
	// The service the client actually used: ?service= on the info/refs GET,
	// the /git-* path suffix on the POSTs that follow it.
	svc := gitService(r)
	if !knownRepo(repo) {
		_, _ = s.Obs.AddHTTP(r, "https", map[string]any{"token": tok, "repo": repo, "service": svc, "result": "404"})
		fxlib.WriteJSON(w, 404, map[string]string{"message": "not found"})
		return
	}
	body, _ := s.Obs.AddHTTP(r, "https", map[string]any{
		"token": tok, "repo": repo, "service": svc,
	})
	status, hdr, out, err := gitHTTPBackend(s.Root, repo, r, body)
	if err != nil {
		fxlib.WriteJSON(w, 500, map[string]string{"message": err.Error()})
		return
	}
	for k, v := range hdr {
		w.Header()[k] = v
	}
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

// gitService returns the git smart-HTTP service the request addresses:
// the ?service= parameter on the info/refs GET, or the /git-* path suffix
// on the POSTs that follow it.
func gitService(r *http.Request) string {
	if s := r.URL.Query().Get("service"); s != "" {
		return s
	}
	for _, svc := range []string{"git-upload-pack", "git-receive-pack"} {
		if strings.HasSuffix(r.URL.Path, "/"+svc) {
			return svc
		}
	}
	return ""
}

func knownRepo(repo string) bool {
	for _, x := range Repos {
		if x == repo {
			return true
		}
	}
	return false
}

// gitHTTPBackend runs `git http-backend` as CGI for repo. The repo path inside
// GIT_PROJECT_ROOT is <repo>.git; PATH_INFO keeps the .git suffix because
// http-backend resolves it under the project root.
func gitHTTPBackend(root, repo string, r *http.Request, body []byte) (int, http.Header, []byte, error) {
	env := []string{
		"GIT_PROJECT_ROOT=" + filepath.Join(root, "git"),
		"GIT_HTTP_EXPORT_ALL=1",
		"REQUEST_METHOD=" + r.Method,
		"PATH_INFO=/" + repo + ".git" + gitRemainder(r.URL.Path, repo),
		"QUERY_STRING=" + r.URL.RawQuery,
		"REMOTE_USER=agent",
		"REMOTE_ADDR=127.0.0.1",
		"GIT_PROTOCOL=" + r.Header.Get("Git-Protocol"),
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		env = append(env, "CONTENT_TYPE="+ct)
	}
	env = append(env, "CONTENT_LENGTH="+strconv.Itoa(len(body)))
	env = append(env, "HOME="+root, "PATH="+os.Getenv("PATH"))

	cmd := exec.Command("git", "http-backend")
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(body)
	var out bytes.Buffer
	cmd.Stdout = &out
	var serr bytes.Buffer
	cmd.Stderr = &serr
	if err := cmd.Run(); err != nil {
		return 0, nil, nil, fmt.Errorf("git http-backend: %w: %s", err, serr.String())
	}

	// Parse CGI response: headers, blank line, body.
	raw := out.Bytes()
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	sep := 4
	if idx < 0 {
		idx = bytes.Index(raw, []byte("\n\n"))
		sep = 2
	}
	if idx < 0 {
		return 0, nil, nil, fmt.Errorf("git http-backend: no CGI headers in output")
	}
	status := 200
	hdr := http.Header{}
	for _, line := range strings.Split(string(raw[:idx]), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		k, v, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		v = strings.TrimSpace(v)
		if strings.EqualFold(k, "Status") {
			status, _ = strconv.Atoi(strings.Fields(v)[0])
			continue
		}
		hdr.Add(k, v)
	}
	return status, hdr, raw[idx+sep:], nil
}

func gitRemainder(path, repo string) string {
	p := strings.TrimPrefix(path, "/"+repo+".git")
	if p == "" {
		return "/"
	}
	return p
}

// git runs a git command with HOME isolated to root (tests must not touch the
// user's git config or objects).
func git(root, dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(),
		"HOME="+root,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Fixture Third Party",
		"GIT_AUTHOR_EMAIL=thirdparty@fixtures.invalid",
		"GIT_COMMITTER_NAME=Fixture Third Party",
		"GIT_COMMITTER_EMAIL=thirdparty@fixtures.invalid",
		// Fixed dates make seeded (and third-party) commits byte-deterministic,
		// so __reset reproduces the identical state digest.
		"GIT_AUTHOR_DATE=2026-01-01T00:00:00Z",
		"GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
	)
	var out, serr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &serr
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, serr.String())
	}
	return out.String(), nil
}

// seedRepo creates a bare repo with a main branch holding deterministic seed
// files, via a scratch working clone.
func seedRepo(bare, repo string) error {
	// bare is <Root>/git/<owner>/<repo>.git → root = <Root>
	root := filepath.Dir(filepath.Dir(filepath.Dir(bare)))
	if err := os.MkdirAll(filepath.Dir(bare), 0o755); err != nil {
		return err
	}
	if _, err := git(root, "", "init", "--bare", "-b", "main", bare); err != nil {
		return err
	}
	scratch, err := os.MkdirTemp(filepath.Join(root, "scratch"), "seed-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	if _, err := git(root, "", "clone", "--quiet", bare, scratch); err != nil {
		return err
	}
	files := map[string]string{
		"README.md":   "# " + repo + "\n\nSeed content of " + repo + ".\n",
		"src/main.py": "def main():\n    return " + strconv.Quote(repo) + "\n",
	}
	for name, content := range files {
		p := filepath.Join(scratch, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return err
		}
	}
	if _, err := git(root, scratch, "add", "-A"); err != nil {
		return err
	}
	if _, err := git(root, scratch, "commit", "--quiet", "-m", "seed "+repo); err != nil {
		return err
	}
	if _, err := git(root, scratch, "push", "--quiet", "origin", "HEAD:refs/heads/main"); err != nil {
		return err
	}
	return nil
}

// forEachRef lists "refname objectname" lines for a repo.
func (s *Server) forEachRef(repo string) string {
	out, err := git(s.Root, "", "-C", s.gitDir(repo), "for-each-ref", "--format=%(refname) %(objectname)")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// refExists reports whether refs/heads/<branch> resolves in the repo.
func (s *Server) refExists(repo, branch string) bool {
	_, err := git(s.Root, "", "-C", s.gitDir(repo), "rev-parse", "--verify", "--quiet", "refs/heads/"+branch)
	return err == nil
}

// adminCommit fabricates a third-party commit on branch via a scratch clone.
func (s *Server) adminCommit(repo, branch, message string, files map[string]string) (string, error) {
	bare := s.gitDir(repo)
	scratch, err := os.MkdirTemp(filepath.Join(s.Root, "scratch"), "thirdparty-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	if _, err := git(s.Root, "", "clone", "--quiet", bare, scratch); err != nil {
		return "", err
	}
	if _, err := git(s.Root, scratch, "checkout", "--quiet", "-B", branch, "origin/"+branch); err != nil {
		// New branch from default HEAD.
		if _, err2 := git(s.Root, scratch, "checkout", "--quiet", "-B", branch); err2 != nil {
			return "", err2
		}
	}
	for name, content := range files {
		p := filepath.Join(scratch, name)
		if content == "" {
			_ = os.Remove(p)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			return "", err
		}
	}
	if _, err := git(s.Root, scratch, "add", "-A"); err != nil {
		return "", err
	}
	if _, err := git(s.Root, scratch, "commit", "--quiet", "-m", message); err != nil {
		return "", err
	}
	if _, err := git(s.Root, scratch, "push", "--quiet", "origin", "HEAD:refs/heads/"+branch); err != nil {
		return "", err
	}
	out, err := git(s.Root, "", "-C", bare, "rev-parse", "refs/heads/"+branch)
	return strings.TrimSpace(out), err
}

// updateRef points ref at sha, or deletes it when sha is empty.
func (s *Server) updateRef(repo, ref, sha string) error {
	args := []string{"-C", s.gitDir(repo), "update-ref"}
	if sha == "" {
		args = append(args, "-d", ref)
	} else {
		args = append(args, ref, sha)
	}
	_, err := git(s.Root, "", args...)
	return err
}

// installHook writes (script != "") or removes (script == "") a hook in the
// bare repo — the optional pre-receive hook slot of the spec (used by M13.4).
func (s *Server) installHook(repo, name, script string) error {
	if !knownRepo(repo) {
		return fmt.Errorf("unknown repo %s", repo)
	}
	p := filepath.Join(s.gitDir(repo), "hooks", name)
	if script == "" {
		err := os.Remove(p)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		return err
	}
	return nil
}
