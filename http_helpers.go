// Copyright 2014 Ryan Rogers. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package persona

import (
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"

	"github.com/timewasted/go-accept-headers"
)

const (
	ContentTypeHtml  = "text/html; charset=utf-8"
	ContentTypeJson  = "application/json; charset=utf-8"
	ContentTypePlain = "text/plain; charset=utf-8"
)

type CompressedResponseWriter struct {
	http.ResponseWriter
	Compressor io.WriteCloser
	Encoding   string
}

func (crw CompressedResponseWriter) Write(b []byte) (int, error) {
	ce := crw.ResponseWriter.Header().Get("Content-Encoding")
	if crw.Compressor == nil || (ce != "" && ce != crw.Encoding) {
		return crw.ResponseWriter.Write(b)
	}

	crw.ResponseWriter.Header().Add("Vary", "Accept-Encoding")
	crw.ResponseWriter.Header().Set("Content-Encoding", crw.Encoding)
	return crw.Compressor.Write(b)
}

func (crw CompressedResponseWriter) WriteHeader(code int) {
	if crw.Compressor != nil && crw.ResponseWriter.Header().Get("Content-Encoding") == "" {
		crw.ResponseWriter.Header().Add("Vary", "Accept-Encoding")
		crw.ResponseWriter.Header().Set("Content-Encoding", crw.Encoding)
	}
	crw.ResponseWriter.WriteHeader(code)
}

func CompressResponse(f http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		var err error
		var crw = CompressedResponseWriter{
			ResponseWriter: rw,
		}

		encodings := accept.Parse(req.Header.Get("Accept-Encoding"))
		useEncoding, err := encodings.Negotiate("gzip", "deflate")
		if err == nil {
			switch useEncoding {
			case "deflate":
				crw.Compressor, err = flate.NewWriter(rw, flate.DefaultCompression)
			case "gzip":
				crw.Compressor, err = gzip.NewWriterLevel(rw, gzip.DefaultCompression)
			}
			if err == nil && crw.Compressor != nil {
				defer crw.Compressor.Close()
				crw.Encoding = useEncoding
			}
		}

		f(crw, req)
	}
}
