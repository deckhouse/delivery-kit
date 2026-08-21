module example.com/app

go 1.12

require (
	example.com/mylib v0.0.0
	example.com/otherlib v0.0.0
)

replace example.com/mylib => ./mylib

replace example.com/otherlib => ./otherlib
