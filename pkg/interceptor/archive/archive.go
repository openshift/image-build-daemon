package archive

import (
	"archive/tar"
	"bytes"
	"io"
)

// TransformFileFunc is given a chance to transform an arbitrary input file.
type TransformFileFunc func(h *tar.Header, r io.Reader) ([]byte, bool, error)

// FilterArchive transforms the provided input archive to a new archive,
// giving the fn a chance to transform arbitrary files.
func FilterArchive(r io.Reader, w io.Writer, fn TransformFileFunc) error {
	tr := tar.NewReader(r)
	tw := tar.NewWriter(w)

	for {
		h, err := tr.Next()
		if err == io.EOF {
			return tw.Close()
		}
		if err != nil {
			return err
		}

		var body io.Reader = tr
		data, ok, err := fn(h, tr)
		if err != nil {
			return err
		}
		if ok {
			h.Size = int64(len(data))
			body = bytes.NewBuffer(data)
		}

		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if _, err := io.Copy(tw, body); err != nil {
			return err
		}
	}
}

// VisitFileFunc is invoked for each file in the archive. If it returns an error,
// visiting stops and the error is returned.
type VisitFileFunc func(h *tar.Header, r io.Reader) error

// Walk allows a client to walk the provided input archive, invoking fn on each
// file. If an error is returned walking stops immediately.
func Walk(r io.Reader, fn VisitFileFunc) error {
	tr := tar.NewReader(r)

	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		if err := fn(h, tr); err != nil {
			return err
		}
	}
}
