// Portions of this file are derived from Anchore syft
// (https://github.com/anchore/syft/blob/main/syft/cpe/by_specificity.go).
//
// Copyright 2020-present Anchore, Inc. and delivery-kit contributors.
// Licensed under the Apache License, Version 2.0.

package cpe

import (
	"sort"

	"github.com/facebookincubator/nvdtools/wfn"
)

var _ sort.Interface = (*bySpecificity)(nil)

type bySpecificity []CPE

func (b bySpecificity) Len() int { return len(b) }

func (b bySpecificity) Swap(i, j int) { b[i], b[j] = b[j], b[i] }

func (b bySpecificity) Less(i, j int) bool {
	if b[i].vendorSource != b[j].vendorSource {
		return b[i].vendorSource > b[j].vendorSource
	}
	return isMoreSpecific(b[i].attrs, b[j].attrs)
}

func isMoreSpecific(i, j wfn.Attributes) bool {
	iScore := weightedCountForSpecifiedFields(i)
	jScore := weightedCountForSpecifiedFields(j)
	if iScore != jScore {
		return iScore > jScore
	}

	if countFieldLength(i) != countFieldLength(j) {
		return countFieldLength(i) > countFieldLength(j)
	}

	return i.BindToFmtString() < j.BindToFmtString()
}

func countFieldLength(a wfn.Attributes) int {
	return len(a.Part + a.Vendor + a.Product + a.Version + a.TargetSW)
}

func weightedCountForSpecifiedFields(a wfn.Attributes) int {
	checks := []func(a wfn.Attributes) (bool, int){
		func(a wfn.Attributes) (bool, int) { return a.Part != "", 2 },
		func(a wfn.Attributes) (bool, int) { return a.Vendor != "", 3 },
		func(a wfn.Attributes) (bool, int) { return a.Product != "", 4 },
		func(a wfn.Attributes) (bool, int) { return a.Version != "", 1 },
		func(a wfn.Attributes) (bool, int) { return a.TargetSW != "", 1 },
	}

	weightedCount := 0
	for _, check := range checks {
		if isSpecified, weight := check(a); isSpecified {
			weightedCount += weight
		}
	}
	return weightedCount
}
