module example.com/app

go 1.12

require (
	example.com/mylib v0.0.0
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)

replace example.com/mylib => ./mylib

replace gopkg.in/alecthomas/kingpin.v2 => github.com/alecthomas/kingpin v1.3.8-0.20200323085623-b6657d9477a6
