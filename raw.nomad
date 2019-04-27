job "rawr" {
  datacenters = ["dc1"]
  type        = "batch"

  task "example" {
    driver = "raw_exec"

    config {
      # When running a binary that exists on the host, the path must be absolute/
      command = "/bin/touch"
      args    = ["/pk_rocks"]
    }
  }
}
