#!/bin/bash -eux

source_root=$(python -c "from os import path; print(path.abspath(path.join(path.dirname('$0'), '../../..')))")
image=${IMAGE}
keep_containers=""

function show_environment
{
    docker ps
}

function cleanup
{
    if [ "${controller_shared_dir}" ]; then
        rm -rf "${controller_shared_dir}"
    fi

    if [ "${keep_containers}" == "" ]; then
        if [ "${container_id}" ]; then
            docker rm -f "${container_id}"
        fi
    fi
    show_environment
}

if [ "${SHIPPABLE_BUILD_DIR:-}" ]; then
    host_shared_dir="/home/shippable/cache/build-${BUILD_NUMBER}"
    controller_shared_dir="/home/shippable/cache/build-${BUILD_NUMBER}"
else
    host_shared_dir="${source_root}"
    controller_shared_dir=""
fi

if [ "${controller_shared_dir}" ]; then
    cp -a "${SHIPPABLE_BUILD_DIR}" "${controller_shared_dir}"
fi

mkdir -p ${host_shared_dir}/test_data/auth
mkdir -p ${host_shared_dir}/test_data/certs

docker ps

docker_api_version=`docker version --format "{{ .Server.APIVersion }}"`

cat << EOF >${host_shared_dir}/test/integration/group_vars/docker 
---
registry_host_cert_path: ${host_shared_dir}/test_data 
registry_host_auth_path: ${host_shared_dir}/test_data
registry_auth_path: ${host_shared_dir}/test_data 
registry_cert_path: ${host_shared_dir}/test_data 
registry_common_name: ansibleregistry.com
registry_host_port: 5000
private_registry_url: "https://{{ registry_common_name }}:{{ registry_host_port }}"
EOF

container_id=$(docker run \
               -v /var/run/docker.sock:/var/run/docker.sock \
               -v ${host_shared_dir}:/ansible \
               -v ${host_shared_dir}/test_data:/data \
               -e DOCKER_API_VERSION=${docker_api_version} \
               "${image}" create_registry.sh)

registry_ip=$(docker inspect registry --format "{{ .NetworkSettings.IPAddress }}")
echo "Registry IP: ${registry_ip}"

cat << EOF >>${host_shared_dir}/test/integration/group_vars/docker
docker_start_registry: no
EOF

container_id=$(docker run \
               -v /var/run/docker.sock:/var/run/docker.sock \
               -v ${host_shared_dir}:/ansible \
               -v ${host_shared_dir}/test_data:/data \
               -e DOCKER_API_VERSION=${docker_api_version} \
               --add-host=ansibleregistry.com:${registry_ip} \
               "${image}" run.sh)

docker rm --force registry
docker ps
