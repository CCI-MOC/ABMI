### Agentless Bare-Metal Introspection

#### Project Overview
To enable non-intrusive introspection of a bare-metal instances` software stack.

#### Architecture
![picture alt](https://github.com/CCI-MOC/ABMI/blob/master/figures/abmi-arch.jpg "Title is optional")

#### Prototype Implementation
![picture alt](https://github.com/CCI-MOC/ABMI/blob/master/figures/abmi-implementation.jpg "Title is optional")

#### Major Components
1. __M2 Services:__ Our system is based on M2 and leverages the services provided by M2 such as node provisioning and snap creation.
2. __Ceph:__ We use Ceph as our distributed image database. It stores all the golden images as well as snapshots of those images.
3. __Crawler:__ We leveraged the Agentless System Crawler from IBM that can generate frames by running on a mounted image.
4. __Vulnerability Detection Module:__ We built a Vulnerability Detection module that takes the generated frame from Agentless System Crawler as an input and creates a vulnerability report.

#### Workflow:
* The user invokes an introspection through the CLI -- specifies the project and node.
* Picasso is the RESTful interface of M2 and receives requests from either UI or CLI and forwards it to Einstein.
* Einstein is a service of M2 that is responsible for all the computations and performing operations in the back end.
* Once Einstein receives the introspection request from Picasso, it triggers a __snap creation__ command of M2. This command creates a snapshot of the provided node and stores the copy in Ceph.
* Einstein then invokes a map and mount function, which maps the image to a system and then mounts it there.
* The Agentless System Crawler receives the mount point as a parameter and runs on the mounted image. It generates a Frame that contains all the metadata information of the OS running on the node along with package information of the system.
* A security check is performed on this generated frame by passing it to our Vulnerability Detection module. 
* The Vulnerability Detection module contains an in-memory database that has the security notices of all the vulnerable packages, obtained from public repositories like CVE or Ubuntu Security Notices. 
* The module compares the packages from the Frame to the database and generates a Vulnerability Report that contains the information about all the vulnerable packages within the system along with the severity of security threats for each package. It also contains information about the OS and the total number of packages within the system.
* This vulnerability report is then sent back to the user through either CLI.

#### Requirements
* HIL: Hardware Isolation Layer.
* Ceph cluster (for image management).
* A pre-computed SQLitedatabase with solftware vulnerabilities with known vulnerabilities.

#### Setup and Deployment
See https://github.com/CCI-MOC/ABMI/blob/master/deploy.txt.

#### Related Links
* https://github.com/CCI-MOC/m2
* https://github.com/CCI-MOC/hil
* https://github.com/cloudviz/agentless-system-crawler
* https://github.com/ceph/ceph
