# Build firmware

First
> cd release/src-rt-6.x.4708

Edit makefile

RT-AC68U:

> `export MERLINR_NAME := RTAC68U`
`export MERLINR_VER_MAJOR :=R`

EA6700:

> `export MERLINR_NAME := EA6700`
`export MERLINR_VER_MAJOR :=B`

Do make

> make rt-ac68u

