{% if include.header %}
{% assign header = include.header %}
{% else %}
{% assign header = "###" %}
{% endif %}
Create a signed OCI attestation and attach it to a container image.

The predicate file is wrapped in an in-toto Statement v1, then in a DSSE envelope, signed with the specified key, and pushed to the container registry as an OCI artifact with a subject reference to the parent image.

{{ header }} Syntax

```shell
werf attest sign [options]
```

{{ header }} Options

```shell
      --container-registry-mirror=[]
            (Buildah-only) Use specified mirrors for docker.io
      --digest=""
            Digest of the parent image (e.g. sha256:abc123)
      --docker-config=""
            Specify docker config directory path. Default $WERF_DOCKER_CONFIG or $DOCKER_CONFIG or  
            ~/.docker (in the order of priority)
            Command needs granted permissions to read and push images into the specified repo
      --home-dir=""
            Use specified dir to store werf cache files and dirs (default $WERF_HOME or ~/.werf)
      --image=""
            Image name for artifact indexing (required)
      --insecure-registry=false
            Use plain HTTP requests when accessing a registry (default $WERF_INSECURE_REGISTRY)
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
      --log-quiet=false
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
      --predicate=""
            Path to the predicate file (required)
      --repo=""
            Container registry storage address (default $WERF_REPO)
      --repo-container-registry=""
            Choose repo container registry implementation.
            The following container registries are supported: ecr, acr, default, dockerhub, gcr,    
            github, gitlab, harbor, quay.
            Default $WERF_REPO_CONTAINER_REGISTRY or auto mode (detect container registry by repo   
            address).
      --repo-docker-hub-password=""
            repo Docker Hub password (default $WERF_REPO_DOCKER_HUB_PASSWORD)
      --repo-docker-hub-token=""
            repo Docker Hub token (default $WERF_REPO_DOCKER_HUB_TOKEN)
      --repo-docker-hub-username=""
            repo Docker Hub username (default $WERF_REPO_DOCKER_HUB_USERNAME)
      --repo-github-token=""
            repo GitHub token (default $WERF_REPO_GITHUB_TOKEN)
      --repo-harbor-password=""
            repo Harbor password (default $WERF_REPO_HARBOR_PASSWORD)
      --repo-harbor-username=""
            repo Harbor username (default $WERF_REPO_HARBOR_USERNAME)
      --repo-quay-token=""
            repo quay.io token (default $WERF_REPO_QUAY_TOKEN)
      --sign-cert=""
            The leaf certificate as path to PEM file or base64-encoded PEM (default $WERF_SIGN_CERT)
      --sign-intermediates=""
            The intermediate certificates as path to PEM file or base64-encoded PEM (default        
            $WERF_SIGN_INTERMEDIATES)
      --sign-key=""
            The private signing key as path to PEM file, base64-encoded PEM or hashivault://[KEY]   
            (default $WERF_SIGN_KEY)
      --sign-manifest=false
            Enable image manifest signing (default $WERF_SIGN_MANIFEST).
            When enabled,
            the private signing key must be specified with --sign-key option and
            the certificate must be specified with --sign-cert option
      --skip-tls-verify-registry=false
            Skip TLS certificate validation when accessing a registry (default                      
            $WERF_SKIP_TLS_VERIFY_REGISTRY)
      --tag=""
            Tag of the parent image (resolved to digest)
      --tmp-dir=""
            Use specified dir to store tmp files and dirs (default $WERF_TMP_DIR or system tmp dir)
      --type=""
            Predicate type: openvex, cyclonedx, spdxjson, slsaprovenance, slsaprovenance1, or a     
            full URI (required)
```

