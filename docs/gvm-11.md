# Using GVM 11 with the PVM tools

## Prerequisites

``` bash
$ sudo apt install redis postgresql
```

## Basic install

In brief, follow the directions at https://launchpad.net/~mrazavi/+archive/ubuntu/gvm, with the following notes:

* During the install, the package will enable a Redis socket and initialize the Postgres database. It's fine to stick with the defaults, or choose your own password if you prefer.
* Before running `$ greenbone-nvt-sync`, you'll need to change the ownership of `/var/lib/openvas/plugins` to the user you expect to be running your VM system. Basically anything but root, because that script will complain (and fail) if you run it as root.
* Add to `/etc/default/gvmd`: `DAEMON_ARGS="--listen-group ubuntu"` (replace `ubuntu` with the user group of your VM system user) then restart gvmd with `$ sudo systemctl restart gvmd`. This will let the new `run-openvas.sh` script access the GVM socket.
* Assuming you want to get into the Greenbone web UI from another system, you'll need to update `/etc/default/gsad` to listen on `0.0.0.0` then restart GSA with `$ sudo systemctl restart gsad`. At that point you'll be able to reach the UI at (**note new port!**) `https://<ipaddr>:9392`

## Major differences from the print book

* The system is no longer called **OpenVAS** -- it's **Greenbone Vulnerability Management (GVM)**. The scanner process itself is still OpenVAS however. For continuity I'm still calling the script `run-openvas.sh` even though it is talking to GVM.
* `omp` is now deprecated -- CLI access to the scanner system is via `gvm-cli`. It doesn't support all of the same CLI arguments so there is now a bit more XML in `run-openvas.sh`. Notably, the `<get_reports/>` tag now includes `details="1"` as otherwise GVM will only return a summary report.
* Relatedly, `omp.config` is now `gvm.config`.
* Programmatic access to GVM via Python is now possible! While I've minimized the changes to the OpenVAS scripts for the sake of continuity, it's entirely plausible now to rewrite `openvas-insert.py` to both conduct the scan and insert the results into Mongo. To use the Python library, check out the docs at https://python-gvm.readthedocs.io/en/latest/.
* As alluded to above, `greenbone-nvt-sync` must **not** be run as root. I've updated `update-tools.sh` to ensure it's run as a nonprivileged user.