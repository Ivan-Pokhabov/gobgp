// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"testing"

	"github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
)

func TestFormatDefinedSetCommunityMatchType(t *testing.T) {
	sets := []*api.DefinedSet{
		{
			Name: "cs1",
			List: []string{
				"^65000:100$",
				"^65000:.*$",
			},
		},
	}

	plain := formatDefinedSet(true, "COMMUNITY", 0, sets, false)
	assert.NotContains(t, plain, "MATCH")
	assert.NotContains(t, plain, "fixed-as-wildcard")

	debug := formatDefinedSet(true, "COMMUNITY", 0, sets, true)
	assert.Contains(t, debug, "MATCH")
	assert.Contains(t, debug, "exact")
	assert.Contains(t, debug, "fixed-as-wildcard")
}

func TestFormatDefinedSetExtCommunityMatchType(t *testing.T) {
	sets := []*api.DefinedSet{
		{
			Name: "ecs1",
			List: []string{
				"rt:^65000:(100|200)$",
				`rt:^\d+:(100|200)$`,
			},
		},
	}

	debug := formatDefinedSet(true, "EXT-COMMUNITY", 0, sets, true)
	assert.Contains(t, debug, "MATCH")
	assert.Contains(t, debug, "as-bitmap")
	assert.Contains(t, debug, "local-bitmap")
}
