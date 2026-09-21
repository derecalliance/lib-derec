package schema

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestFileDescriptorSetDecodes(t *testing.T) {
	var fds descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(FileDescriptorSet, &fds); err != nil {
		t.Fatalf("descriptor set does not decode: %v", err)
	}
	if got := len(fds.File); got < 18 {
		t.Fatalf("expected at least 18 files in the closure, got %d", got)
	}
}

func TestProtoFilesAreEmbedded(t *testing.T) {
	entries, err := Proto.ReadDir("proto")
	if err != nil {
		t.Fatalf("proto directory not embedded: %v", err)
	}
	if len(entries) != 18 {
		t.Fatalf("expected 18 proto files, got %d", len(entries))
	}
}
