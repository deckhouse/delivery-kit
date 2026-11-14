package nativegate

// refusedLoaderFiles are the files of this image that would answer before anything the
// gate resolved: the preload list, and the cache of a partial runtime whose loader stands
// in another image. Where this image holds its own loader, the cache it reads is named by
// that loader's bytes and refused there instead; the path here is the one glibc's rtld is
// built with, which is all there is to go on when no loader of this image names it.
func refusedLoaderFiles(partial bool, loader *loaderModel) []string {
	if partial && loader == nil {
		return []string{"/etc/ld.so.preload", "/etc/ld.so.cache"}
	}

	return []string{"/etc/ld.so.preload"}
}

// missingRuntimeDependencyError is a name a file needs that this image holds no file
// for. It is the one runtime refusal a partial runtime tolerates, so it is answered as a
// value the caller can recognize rather than as text.
type missingRuntimeDependencyError struct {
	soname string
}

func (e missingRuntimeDependencyError) Error() string {
	return "missing runtime dependency " + e.soname
}
