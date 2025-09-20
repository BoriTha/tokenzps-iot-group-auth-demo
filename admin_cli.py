#!/usr/bin/env python3
import cmd, os, time, subprocess, requests
from docker import from_env as docker_from_env
from docker.errors import NotFound

FOG_URL = os.environ.get("FOG_NODE_URL", "http://localhost:5000")
DOCKER_NETWORK = "iot_net"
DEVICE_SERVICE_PATH = "./device_service"
DEVICE_IMAGE_TAG = "device_service_image"

class AdminShell(cmd.Cmd):
    intro = "Fog Admin Shell. Type help for commands."
    prompt = "fog-admin> "

    def do_list(self, line):
        "List all device IDs (static & dynamic) and whether they’re registered in Fog"
        # 1) fetch Fog’s registry
        try:
            fog_urls = requests.get(f"{FOG_URL}/get_device_urls").json()
        except Exception as e:
            print("Error fetching Fog registry:", e)
            fog_urls = {}

        # 2) inspect all containers
        client   = docker_from_env()
        all_conts = client.containers.list(all=True)

        # 3) collect device IDs from either:
        #    – admin‐created containers named 'device_<n>'
        #    – Compose‐managed services with label com.docker.compose.service=device_<n>
        dev_ids = set()
        for c in all_conts:
            # dynamic devices
            if c.labels.get("com.final.admin_created") == "true":
                dev_ids.add(c.name)
            # static devices via Compose service label
            svc = c.labels.get("com.docker.compose.service")
            if svc and svc.startswith("device_"):
                dev_ids.add(svc)

        # 4) sort by numeric suffix
        dev_list = sorted(dev_ids, key=lambda d: int(d.split("_")[-1]))

        # 5) print status
        for dev in dev_list:
            status = "registered" if dev in fog_urls else "unregistered"
            print(f"{dev:<10} → {status}")



    def do_terminate(self, line):
        "Terminate the current group‐auth session on the Fog"
        r = requests.post(f"{FOG_URL}/terminate_session")
        print(r.status_code, r.json())

    def do_remove_device(self, line):
        "Remove a device from Fog (and revoke its token), kill its container, and delete its storage file: remove_device <device_id>"
        dev_id = line.strip()
        if not dev_id:
            print("Usage: remove_device <device_id>")
            return

        # 1) If device is in the active session, revoke its token share
        try:
            status = requests.get(f"{FOG_URL}/status", timeout=5).json()
            active = status.get("active_session_info") or {}
            legits = active.get("legitimate_devices_for_this_token", [])
            if dev_id in legits:
                print(f"Revoking token for {dev_id} …")
                r_rev = requests.post(
                    f"{FOG_URL}/revoke_device_token",
                    json={"device_id": dev_id},
                    timeout=5
                )
                try:
                    print("  revoke →", r_rev.status_code, r_rev.json())
                except ValueError:
                    print("  revoke →", r_rev.status_code, r_rev.text)
        except Exception as e:
            print("Error checking/revoking session token:", e)

        # 2) Tell Fog to remove the device completely
        try:
            r = requests.post(
                f"{FOG_URL}/remove_device",
                json={"device_id": dev_id},
                timeout=5
            )
            print("Fog remove_device →", r.status_code, r.json())
        except Exception as e:
            print("Error calling Fog /remove_device:", e)

        # 3) Stop & remove its Docker container
        try:
            subprocess.run(["docker", "rm", "-f", dev_id], check=True)
            print(f"Container {dev_id} removed.")
        except subprocess.CalledProcessError:
            print(f"Container {dev_id} not found or already removed.")
        except Exception as e:
            print(f"Error removing container {dev_id}:", e)

        # 4) Delete its local storage JSON
        storage_file = os.path.join(
            os.getcwd(),
            "storage",
            f"device_{dev_id}_storage.json"
        )
        if os.path.exists(storage_file):
            try:
                os.remove(storage_file)
                print(f"Deleted storage file: {storage_file}")
            except Exception as e:
                print(f"Error deleting storage file {storage_file}:", e)
        else:
            print(f"No storage file found at {storage_file}")



    def do_add_device(self, line):
        """
        add_device

        1) Fetch current fog registry.
        2) Pick the next free device_N (skipping fog & Docker).
        3) Locate or build the device_service image.
        4) Launch the new container (auto‐register disabled).
        """
        client = docker_from_env()

        # 1) Get current fog‐known devices
        try:
            fog_urls = requests.get(f"{FOG_URL}/get_device_urls").json()
        except Exception as e:
            print("Error fetching Fog registry:", e)
            fog_urls = {}

        # 2) Compute next free device_N
        fog_ids = {
            int(d.split("_")[-1])
            for d in fog_urls
            if d.startswith("device_") and d.split("_")[-1].isdigit()
        }
        all_names = {c.name for c in client.containers.list(all=True)}
        n = max(fog_ids or [0])
        while True:
            n += 1
            candidate = f"device_{n}"
            if candidate not in all_names and candidate not in fog_urls:
                dev_id = candidate
                break
        print("New device ID:", dev_id)

        # 3) Find an image to use:
        image_tag = None
        # 3a) Prefer the image tag from an existing device_1 container
        for cont in client.containers.list(all=True):
            if cont.name == "device_1" and cont.image.tags:
                image_tag = cont.image.tags[0]
                break
        # 3b) Else any local image tagged with 'device_service'
        if not image_tag:
            for img in client.images.list():
                for tag in img.tags:
                    if "device_service" in tag:
                        image_tag = tag
                        break
                if image_tag:
                    break
        # 3c) Else build fresh
        if not image_tag:
            print("Building device image from", DEVICE_SERVICE_PATH, "...")
            try:
                image_obj, _ = client.images.build(
                    path=DEVICE_SERVICE_PATH,
                    tag=DEVICE_IMAGE_TAG,
                    rm=True
                )
                image_tag = DEVICE_IMAGE_TAG
                print("Built image:", image_tag)
            except Exception as e:
                print("Failed to build device image:", e)
                return
        print("Using image:", image_tag)

        # 4) Discover Docker network from fog_service container
        fog_cont = None
        for c in client.containers.list(all=True):
            if "fog_service" in c.name:
                fog_cont = c
                break
        if fog_cont:
            nets = list(
                fog_cont.attrs["NetworkSettings"]["Networks"].keys()
            )
            if not nets:
                print("ERROR: fog_service not attached to any network")
                return
            docker_network = nets[0]
        else:
            docker_network = DOCKER_NETWORK
            print("Warning: using fallback network", docker_network)

        # 5) Launch new device container
        print(f"Starting container {dev_id} …")
        try:
            client.containers.run(
                image_tag,
                name=dev_id,
                detach=True,
                network=docker_network,
                volumes={
                    os.path.abspath("storage"): {
                        "bind": "/app/storage",
                        "mode": "rw"
                    }
                },
                environment={
                    "DEVICE_ID": dev_id,
                    "DEVICE_ROLE": "base",
                    "DISABLE_AUTO_REGISTER": "true",
                    "FOG_NODE_URL": "http://fog_service:5000",
                    "DEVICE_FLASK_PORT": "5001"
                },
                labels={
                    "com.docker.compose.project": "final",
                    "com.final.admin_created": "true"
                },
                restart_policy={"Name": "unless-stopped"}
            )
        except Exception as e:
            print("Failed to start container:", e)
            return

        # 6) Wait a bit, then check auto‐registration
        time.sleep(7)
        try:
            urls2 = requests.get(f"{FOG_URL}/get_device_urls").json()
        except Exception as e:
            print("Error re‐fetching Fog registry:", e)
            urls2 = {}

        if dev_id in urls2:
            print(f"{dev_id} successfully registered with Fog.")
        else:
            print(f"{dev_id} did NOT auto-register; you can call:")
            print(f"  device {dev_id} trigger_register")



    def do_restart(self, line):
        """
        Restart the entire stack:
           docker-compose down --remove-orphans && docker-compose up -d
        """
        print("Stopping stack (with remove-orphans)…")
        try:
            subprocess.run(
                ["docker-compose", "down", "--remove-orphans"],
                check=True
            )
        except FileNotFoundError:
            subprocess.run(
                ["docker", "compose", "down", "--remove-orphans"],
                check=True
            )
        print("Starting stack (detached)…")
        try:
            subprocess.run(
                ["docker-compose", "up", "-d"],
                check=True
            )
        except FileNotFoundError:
            subprocess.run(
                ["docker", "compose", "up", "-d"],
                check=True
            )
        print("Stack restarted.  All dynamic devices will be cleaned up.")




    def do_resync(self, line):
        # 0) ensure our thresholds match current enrollment
        print("0) Auto‐adjusting thresholds…")
        resp0 = requests.post(f"{FOG_URL}/auto_update_thresholds", timeout=5)
        print("   →", resp0.status_code, resp0.json())

        # 1) Trigger Phase 1
        print("1) Triggering Phase 1 on Fog…")
        resp1 = requests.post(
            f"{FOG_URL}/trigger_phase1_polynomial_setup", timeout=10
        )
        print("   →", resp1.status_code, resp1.json())

        # 2) Leader re-authenticating…
        print("2) Leader re-authenticating…")
        self.onecmd("device device_1 reauth")

        # 3) Leader re-running group authentication…
        print("3) Leader re-running group authentication…")
        self.onecmd("device device_1 groupauth")

        # 4) Leader regenerating token…
        print("4) Leader regenerating token…")
        self.onecmd("device device_1 tokengen")

    def do_device(self, line):
        """
        device <id> <send|reauth|groupauth|tokengen|register> [args]
        """
        parts = line.split()
        if len(parts) < 2:
            print(self.do_device.__doc__); return
        dev, cmdn, *args = parts

        # map command → endpoint + JSON body
        if cmdn == "send":
            ep, body = "/trigger_send_data", {"data": " ".join(args) or input("Data> ")}
        elif cmdn == "reauth":
            ep, body = "/trigger_reauth", {}
        elif cmdn == "groupauth":
            ep, body = "/trigger_group_auth", {}
            if args: body["member_ids"] = args[0].split(",")
        elif cmdn == "tokengen":
            ep, body = "/trigger_token_gen", {}
            if args: body["legit_device_ids"] = args[0].split(",")
        elif cmdn == "register":
            ep, body = "/trigger_register", {}
        else:
            print("Unknown device command:", cmdn); return

        client = docker_from_env()
        try:
            # try simple name lookup first
            cont = client.containers.get(dev)
        except NotFound:
            # fallback: look for a container with compose‐service label == dev
            cont = None
            for c in client.containers.list(all=True):
                labels = c.attrs["Config"].get("Labels") or {}
                if labels.get("com.docker.compose.service") == dev:
                    cont = c
                    break
            if cont is None:
                print(f"Container {dev} not found"); return

        # build a tiny Python‐in‐container snippet to POST to localhost:5001
        import json as _json
        snippet = (
            "import requests, json;\n"
            f"r = requests.post('http://localhost:5001{ep}', json={_json.dumps(body)});\n"
            "print(r.status_code, r.json())"
        )

        exit_code, output = cont.exec_run(["python3", "-c", snippet])
        print(output.decode().strip())


    def do_add_many(self, line):
        """
        add_many <count>

        Spin up <count> new admin‐created devices, then auto‐register all of them.
        """
        try:
            count = int(line.strip())
            if count <= 0: raise ValueError
        except ValueError:
            print("Usage: add_many <positive-integer>"); return

        created = []
        for _ in range(count):
            # 1) create the container
            self.onecmd("add_device")
            # 2) find the newest admin‐created device (by name suffix)
            client = docker_from_env()
            all_conts = client.containers.list(all=True,
                                               filters={"label":"com.final.admin_created"})
            # sort by numeric suffix
            names = sorted([c.name for c in all_conts],
                           key=lambda n: int(n.split("_")[-1]))
            # skip those already in ‘created’
            for name in names[::-1]:
                if name not in created:
                    new_dev = name
                    created.append(new_dev)
                    break

            # 3) force‐register it
            print(f">>> Registering {new_dev} …")
            self.onecmd(f"device {new_dev} register")
            # 4) small pause to let it appear in Fog registry
            time.sleep(1)

        print("add_many complete; devices created & registered:", created)

    
    def do_cleanup(self, line):
        """
        1) Prune Fog of any device_ids with no corresponding container.
        2) Stop & remove *all* admin‐created device containers,
           delete their storage files, and tell the Fog to forget them.
        """
        client = docker_from_env()

        # 1) Fetch current Fog registry
        try:
            fog_urls = requests.get(f"{FOG_URL}/get_device_urls", timeout=5).json()
        except Exception as e:
            print("Error fetching Fog registry:", e)
            fog_urls = {}

        # 2) Fetch all containers
        all_conts = client.containers.list(all=True)
        cont_names = {c.name for c in all_conts}

        # 3) Prune any fog‐registered IDs that have no container
        stale = [dev for dev in fog_urls if dev not in cont_names]
        if stale:
            print("Pruning stale Fog entries (no container):", stale)
            for dev_id in stale:
                try:
                    r = requests.post(
                        f"{FOG_URL}/remove_device",
                        json={"device_id": dev_id},
                        timeout=5
                    )
                    print(f"  Fog removed {dev_id} →", r.status_code, r.json())
                except Exception as e:
                    print(f"  Error pruning {dev_id}:", e)
        else:
            print("No stale Fog entries to prune.")

        # 4) Now remove all *admin‐created* device containers
        to_remove = client.containers.list(
            all=True,
            filters={"label": "com.final.admin_created"}
        )
        if not to_remove:
            print("No admin‐created device containers found.")
            return

        for cont in to_remove:
            dev_id = cont.name
            print(f"\n--- Removing admin‐created container {dev_id} ---")

            # a) Ask Fog to remove it (again)
            try:
                r = requests.post(
                    f"{FOG_URL}/remove_device",
                    json={"device_id": dev_id},
                    timeout=5
                )
                print("  Fog remove_device:", r.status_code, r.json())
            except Exception as e:
                print("  Error calling Fog /remove_device:", e)

            # b) Stop & remove the container
            try:
                cont.remove(force=True)
                print(f"  Container {dev_id} removed.")
            except Exception as e:
                print(f"  Error removing container {dev_id}:", e)

            # c) Remove its local storage JSON
            #    (path is storage/device_<id>_storage.json)
            storage_file = os.path.join(
                os.getcwd(),
                "storage",
                f"device_{dev_id}_storage.json"
            )
            if os.path.exists(storage_file):
                try:
                    os.remove(storage_file)
                    print(f"  Deleted storage file: {storage_file}")
                except Exception as e:
                    print(f"  Error deleting {storage_file}:", e)
            else:
                print(f"  No storage file found at {storage_file}")

        print("\nCleanup complete.")



        
    def do_status(self, line):
        """
        Show Fog’s current status, including dynamic thresholds.
        """
        try:
            r = requests.get(f"{FOG_URL}/status", timeout=5)
            status = r.json()
        except Exception as e:
            print("Error fetching status:", e)
            return

        # Print current Fog parameters
        params = status.get("parameters", {})
        print("\nFog Parameters:")
        print(f"  Total devices:           "
              f"{params.get('total_devices')}")
        print(f"  Phase1 threshold (t):    "
              f"{params.get('t_phase1')}")
        print(f"  Delegation threshold:    "
              f"{params.get('delegation_t_prime')}")

        # Print device registration/enrollment state
        print("\nRegistered devices: ", status.get("registered_devices", []))
        print("Enrolled devices:   ", status.get("enrolled_devices", []))
        print("Pending enrollment: ", status.get("pending_enrollment", []))

        # Active session info
        sess = status.get("active_session_info", {})
        if sess and sess.get("sessionID"):
            print("\nActive session ID:           "
                  f"{sess.get('sessionID')}")
            print("Devices authenticated for S: "
                  f"{sess.get('authenticated_devices_for_S', [])}")
            print("Session timestamp:           "
                  f"{sess.get('timestamp')}")
        else:
            print("\nNo active session")

        # Group polynomial info
        gp = status.get("group_polynomial", {})
        if gp.get("defining_points"):
            print("\nGroup polynomial P(x):")
            print("  Defining points: ", gp.get("defining_points"))
            print("  Coeffs:          ", gp.get("coeffs"))
            print("  Degree:          ", gp.get("degree"))
            print("  Secret S=P(0):   ", gp.get("secret_S"))
        else:
            print("\nGroup polynomial not yet set up")

        # Delegation polynomial & offsets
        if status.get("delegation_poly_coeffs") is not None:
            print("\nDelegation SSS polynomial coeffs: "
                  f"{status.get('delegation_poly_coeffs')}")
        if status.get("device_offsets"):
            print("Device offsets: ", status.get("device_offsets"))

        # Suspicious devices
        sus = status.get("suspicious_devices", [])
        if sus:
            print("\nSuspicious devices from last auth: ", sus)
        print()


    def do_set_thresholds(self, line):
        parts = line.split()
        if not parts:
            print("Usage: set_thresholds <t_phase1> [delegation_t_prime]")
            return

        payload = {}
        # parse t_phase1
        try:
            payload["t_phase1"] = int(parts[0])
        except ValueError:
            print("Error: t_phase1 must be an integer")
            return

        # optional delegation_t_prime
        if len(parts) > 1:
            try:
                payload["delegation_t_prime"] = int(parts[1])
            except ValueError:
                print("Error: delegation_t_prime must be an integer")
                return

    def do_auto_set_thresholds(self, line):
        """
        auto_set_thresholds

        Ask the Fog to recompute its thresholds based on current device count.
        """
        try:
            r = requests.post(f"{FOG_URL}/auto_update_thresholds", timeout=5)
        except Exception as e:
            print("Error calling auto_update_thresholds:", e)
            return

        # Print status
        print(f"HTTP {r.status_code}")

        # Try to parse JSON, otherwise dump raw text
        try:
            data = r.json()
            print(data)
        except ValueError:
            print("Non-JSON response body:")
            print(r.text)

    def do_revoketoken(self, line):
        """
        revoketoken <device_id>

        Revoke the given device’s Phase-6 token share
        without terminating the overall session.
        """
        dev = line.strip()
        if not dev:
            print("Usage: revoketoken <device_id>")
            return

        try:
            r = requests.post(
                f"{FOG_URL}/revoke_device_token",
                json={"device_id": dev},
                timeout=5
            )
            print(r.status_code, r.json())
        except Exception as e:
            print("Error calling revoke_device_token:", e)

    def do_resync_session(self, line):

        # 1) Leader re‐authenticate
        print("1) Leader re-authenticating…")
        self.onecmd("device device_1 reauth")

        # 2) Leader group‐auth (Phase 4)
        print("2) Leader re-running group authentication…")
        self.onecmd("device device_1 groupauth")

        # 3) Leader token gen (Phase 5)
        print("3) Leader regenerating token…")
        self.onecmd("device device_1 tokengen")



    def do_exit(self, line): return True
    def do_quit(self,  line): return True
    def do_EOF(self,   line): return True

if __name__ == "__main__":
    AdminShell().cmdloop()
