package source

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
)

var _ FileResolver = (*fileBufferResolver)(nil)

func newFileBufferResolver(path string, buf *bytes.Buffer) (*fileBufferResolver, error) {
	ft := filetree.NewFileTree()
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	_, err = ft.AddFile(file.Path(path))
	if err != nil {
		return nil, err
	}

	return &fileBufferResolver{
		path:     path,
		reader:   newFileBufferReader(buf),
		fileTree: ft,
	}, nil
}

type fileBufferResolver struct {
	path     string
	reader   fileBufferReader
	fileTree *filetree.FileTree
}

func (r *fileBufferResolver) FileContentsByLocation(location Location) (io.ReadCloser, error) {
	if location.Coordinates.RealPath != r.path {
		return nil, errors.New("path is not match given path")
	}

	return r.reader, nil
}

func (r *fileBufferResolver) HasPath(s string) bool {
	panic("not implement")
}

func (r *fileBufferResolver) FilesByPath(paths ...string) ([]Location, error) {
	var result = make([]Location, 0)
	// nothing to do, we don't care a specified path.
	return result, nil
}

func (r *fileBufferResolver) FilesByGlob(patterns ...string) ([]Location, error) {
	var result = make([]Location, 0)

	for _, pattern := range patterns {
		var globResults, err = r.fileTree.FilesByGlob(pattern, filetree.FollowBasenameLinks)
		if err != nil {
			return nil, err
		}
		for _, globResult := range globResults {
			var loc = Location{
				Coordinates: Coordinates{
					RealPath: string(globResult.Reference.RealPath),
				},
				ref: globResult.Reference,
			}
			result = append(result, loc)
		}
	}

	return result, nil
}

func (r *fileBufferResolver) FilesByMIMEType(types ...string) ([]Location, error) {
	var result = make([]Location, 0)
	// nothing to do, we don't care a specified types.
	return result, nil
}

func (r *fileBufferResolver) RelativeFileByPath(_ Location, path string) *Location {
	panic("not implement")
}

func (r *fileBufferResolver) AllLocations() <-chan Location {
	panic("not implement")
}

func (r *fileBufferResolver) FileMetadataByLocation(location Location) (FileMetadata, error) {
	panic("not implement")
}

func newFileBufferReader(buf *bytes.Buffer) fileBufferReader {
	return fileBufferReader{
		Buffer: buf,
	}
}

type fileBufferReader struct {
	*bytes.Buffer
}

func (r fileBufferReader) Close() error {
	r.Buffer.Reset()
	return nil
}
