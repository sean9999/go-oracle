package subcommand_test

const AGED_MORNING_CONF = "../../../testdata/aged-morning.conf.toml"
const GREEN_BROOK_CONF = "../../../testdata/green-brook.conf.toml"
const AGED_MORNING_PEER = `{
	"self": {
		"nick": "aged-morning",
		"pub": "c90872a2dda2d9043cf93c911cc0949c9eb29dc62799c8a2350c85b3bde1653c88da1f0828db45d0187be6a782e7d5abee8f431b501d62b65f5d09cb99830222"
	},
	"peers": {
		"aged-morning": {
			"nick": "aged-morning",
			"pub": "c90872a2dda2d9043cf93c911cc0949c9eb29dc62799c8a2350c85b3bde1653c88da1f0828db45d0187be6a782e7d5abee8f431b501d62b65f5d09cb99830222"
		},
		"green-brook": {
			"nick": "green-brook",
			"pub": "044cf4b0be1d933ff30cd78f5510f11322d9f9dfcd138b461662eba1abb1689772453711141335f928e9fb2ae7ec0afe5a7b714a4b762731e515b9b7bfce2c60"
		}
	}
}
`

const GREEN_BROOK_PEERS = `{
  "aged-morning": "c90872a2dda2d9043cf93c911cc0949c9eb29dc62799c8a2350c85b3bde1653c88da1f0828db45d0187be6a782e7d5abee8f431b501d62b65f5d09cb99830222"
}`
