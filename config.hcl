plugin "nomad-experiment" {
  config {}
}

client {
  options = {
    "driver.whitelist" = "triton"
  }
}

consul {
  address = "0.0.0.0:8500"
}
