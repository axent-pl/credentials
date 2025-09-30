package credentials

import "fmt"

func ArtifactWithKind(artifacts []Artifact, kind ArtifactKind) (Artifact, error) {
	for _, artartifact := range artifacts {
		if artartifact.Kind == kind {
			return artartifact, nil
		}
	}
	return Artifact{}, fmt.Errorf("missing artifact %s", kind)
}
