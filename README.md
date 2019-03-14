# gotc

A TC (Linux traffic control) package for Go

## Install

```
go get -u github.com/chenquanquan/gotc
```

## Example

``` golang
package main

import (
    gotc "github.com/chenquanquan/gotc"
)

func main() {
    gotc.SetBandWidthLimit("192.168.1.99", "100Mbit", "1Mbit")
    gotc.SetBandWidthLimitIpv6("1234:9876:3456:839::284:2222", "10Mbit", "100kbit")
}

```
