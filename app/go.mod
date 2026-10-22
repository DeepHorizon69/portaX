module github.com/alsa/portax

go 1.24

require (
	github.com/jackc/pgx/v5 v5.7.2
	gopkg.in/yaml.v3 v3.0.1
)

// Pin go-internal to v1.13.1 to avoid v1.16.0 requiring go >= 1.25
replace github.com/rogpeppe/go-internal => github.com/rogpeppe/go-internal v1.13.1
exclude github.com/rogpeppe/go-internal v1.16.0
