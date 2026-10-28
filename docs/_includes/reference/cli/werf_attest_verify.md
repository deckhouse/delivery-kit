{% if include.header %}
{% assign header = include.header %}
{% else %}
{% assign header = "###" %}
{% endif %}
Verify a signed attestation attached to a container image.

The attestation is pulled from the container registry, the DSSE signature is verified against the provided public key(s), and the raw predicate JSON is printed to stdout.
If the signature is invalid, the command exits with a non-zero exit code and prints nothing.

When the reference resolves to a multi-platform image index and `--platform` is not set, the attestations of all platforms in the index are verified: a per-platform result table is printed instead of the predicate, and the command succeeds only if every platform carries a valid signed attestation. OpenVEX attestations are image-level: with `--type openvex` the attestation attached to the index itself is verified and `--platform` is not applicable.

{{ header }} Syntax

```shell
werf attest verify [options]
```

{{ header }} Options

```shell
      --container-registry-mirror=[]
            (Buildah-only) Use specified mirrors for docker.io ($WERF_CONTAINER_REGISTRY_MIRROR or  
            $WERF_CONTAINER_REGISTRY_MIRROR_*)
      --digest=""
            Digest of the image (e.g. sha256:abc123)
      --docker-config=""
            Specify docker config directory path. Default $WERF_DOCKER_CONFIG or $DOCKER_CONFIG or  
            ~/.docker (in the order of priority)
            Command needs granted permissions to read images from the specified repo
      --home-dir=""
            Use specified dir to store werf cache files and dirs (default $WERF_HOME or ~/.werf)
      --image=""
            Image name for artifact lookup
      --insecure-registry=false
            Use plain HTTP requests when accessing a registry (default $WERF_INSECURE_REGISTRY)
      --key=[]
            Path to public key PEM file for verification (repeatable, any match = success)
      --log-color-mode="auto"
            Set log color mode.
            Supported on, off and auto (based on the stdout’s file descriptor referring to a        
            terminal) modes.
            Default $WERF_LOG_COLOR_MODE or auto mode.
      --log-debug=false
            Enable debug (default $WERF_LOG_DEBUG).
      --log-pretty=true
            Enable emojis, auto line wrapping and log process border (default $WERF_LOG_PRETTY or   
            true).
      --log-project-dir=false
            Print current project directory path (default $WERF_LOG_PROJECT_DIR)
      --log-quiet=true
            Disable explanatory output (default $WERF_LOG_QUIET).
      --log-terminal-width=-1
            Set log terminal width.
            Defaults to:
            * $WERF_LOG_TERMINAL_WIDTH
            * interactive terminal width or 140
      --log-time=false
            Add time to log entries for precise event time tracking (default $WERF_LOG_TIME or      
            false).
      --log-time-format="2006-01-02T15:04:05Z07:00"
            Specify custom log time format (default $WERF_LOG_TIME_FORMAT or RFC3339 format).
      --log-verbose=false
            Enable verbose output (default $WERF_LOG_VERBOSE).
      --platform=""
            Platform to verify when the reference is a multi-platform index, format:                
            OS/ARCH[/VARIANT]. When omitted for an index, attestations of all its platforms are     
            verified. Not applicable with --type openvex: OpenVEX attestations are image-level and  
            verified at the index digest itself
      --repo=""
            Container registry storage address (default $WERF_REPO)
      --repo-container-registry=""
            Choose repo container registry implementation.
            The following container registries are supported: ecr, acr, default, dockerhub, gcr,    
            github, gitlab, harbor, quay.
            Default $WERF_REPO_CONTAINER_REGISTRY or auto mode (detect container registry by repo   
            address).
      --skip-tls-verify-registry=false
            Skip TLS certificate validation when accessing a registry (default                      
            $WERF_SKIP_TLS_VERIFY_REGISTRY)
      --tag=""
            Tag of the image (resolved to digest)
      --tmp-dir=""
            Use specified dir to store tmp files and dirs (default $WERF_TMP_DIR or system tmp dir)
      --type=""
            Predicate type: cyclonedx, openvex, slsaprovenance, slsaprovenance1, spdxjson, or a     
            full URI (required)
```

