plugin "nomad-driver-triton" {
  config {}
}

client {
  options = {
    "driver.whitelist" = "triton"
  }
}

#acl {
#enabled    = true
#token_ttl  = "30s"
#policy_ttl = "60s"
#}

#vault {
#enabled          = true
#address          = "http://127.0.0.1:8200"
#task_token_ttl   = "1h"
#create_from_role = "nomad-cluster"
#token            = "s.kVpGSrBFvWohtwUzsaxImnCr"
#}

consul {
  address = "0.0.0.0:8500"
}
