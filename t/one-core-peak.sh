#!/bin/bash

args=$*
first_cores=""
taskset_cores=""
first_cores_count=0
nb_threads=1
drives=""

# Default options
latency_cmdline=""

fatal() {
  echo "$@"
  exit 1
}

hint() {
  echo "Warning: $*"
}

info() {
  item=$1
  shift
  echo "${item}: $*"
}

check_root() {
  [[ ${EUID} -eq 0 ]] || fatal "You should be root to run this tool"
}

check_binary() {
  # Ensure the binaries are present and executable
  for bin in "$@"; do
    if [ ! -x ${bin} ]; then
      command -v ${bin} >/dev/null
      [ $? -eq 0 ] || fatal "${bin} doesn't exist or is not executable"
    fi
  done
}

detect_first_core() {
  cpu_to_search="0"
  if [ "${#drives[@]}" -eq 1 ]; then
    device_name=$(block_dev_name ${drives[0]})
    device_dir="/sys/block/${device_name}/device/"
    pci_addr=$(cat ${device_dir}/address)
    pci_dir="/sys/bus/pci/devices/${pci_addr}/"
    cpu_to_search=$(cat ${pci_dir}/local_cpulist | cut -d"," -f 1 | cut -d"-" -f 1)
  else
    hint 'Passed multiple devices. Running on the first core.'
  fi
  core_to_run=$(lscpu  --all -pSOCKET,CORE,CPU | grep ",$cpu_to_search\$" | cut -d"," -f1-2)

  # Detect which logical cpus belongs to the first physical core
  # If Hyperthreading is enabled, two cores are returned
  cpus=$(lscpu  --all -pSOCKET,CORE,CPU | grep "$core_to_run")
  for cpu in ${cpus}; do
    IFS=','
    # shellcheck disable=SC2206
    array=(${cpu})
    if [ ${first_cores_count} -eq 0 ]; then
      first_cores="${array[2]}"
    else
      first_cores="${first_cores} ${array[2]}"
    fi

    first_cores_count=$((first_cores_count + 1))
    unset IFS
  done
  [ ${first_cores_count} -eq 0 ] && fatal "Cannot detect first core"
  taskset_cores=$(echo "${first_cores}" | tr ' ' ',')
}

usage() {
  echo "usage: [options] block_device [other_block_devices]

   -h         : print help
   -l         : enable latency reporting

   example:
      t/one-core-peak.sh /dev/nvme0n1
      t/one-core-peak.sh -l /dev/nvme0n1 /dev/nvme1n1
  "
  exit 0
}

check_args() {
  local OPTIND option
  while getopts "hl" option; do
    case "${option}" in
        h) # Show help
            usage
            ;;
        l) # Report latency
            latency_cmdline="1"
            ;;
        *)
            fatal "Unsupported ${option} option"
            ;;
    esac
  done
  shift $((OPTIND-1))
  [ $# -eq 0 ] && fatal "Missing drive(s) as argument"
  drives="$*"
}

check_drive_exists() {
  # Ensure the block device exists
  [ -b $1 ] || fatal "$1 is not a valid block device"
}

is_nvme() {
  [[ ${*} == *"nvme"* ]]
}

check_poll_queue() {
  # Print a warning if the nvme poll queues aren't enabled
  is_nvme ${drives} || return
  poll_queue=$(cat /sys/module/nvme/parameters/poll_queues)
  [ ${poll_queue} -eq 0 ] && hint "For better performance, you should enable nvme poll queues by setting nvme.poll_queues=32 on the kernel commande line"
}

block_dev_name() {
  echo ${1#"/dev/"}
}

get_sys_block_dir() {
  # Returns the /sys/block/ directory of a given block device
  device_name=$1
  sys_block_dir="/sys/block/${device_name}"
  [ -d "${sys_block_dir}" ] || fatal "Cannot find ${sys_block_dir} directory"
  echo ${sys_block_dir}
}

check_io_scheduler() {
  # Ensure io_sched is set to none
  device_name=$(block_dev_name $1)
  sys_block_dir=$(get_sys_block_dir ${device_name})
  sched_file="${sys_block_dir}/queue/scheduler"
  [ -f "${sched_file}" ] || fatal "Cannot find IO scheduler for ${device_name}"
  grep -q '\[none\]' ${sched_file}
  if [ $? -ne 0 ]; then
    info "${device_name}" "set none as io scheduler"
    echo "none" > ${sched_file}
  fi

}

check_sysblock_value() {
  device_name=$(block_dev_name $1)
  sys_block_dir=$(get_sys_block_dir ${device_name})
  target_file="${sys_block_dir}/$2"
  value=$3
  [ -f "${target_file}" ] || return
  content=$(cat ${target_file} 2>/dev/null)
  if [ "${content}" != "${value}" ]; then
    echo ${value} > ${target_file} 2>/dev/null && info "${device_name}" "${target_file} set to ${value}." || hint "${device_name}: Cannot set ${value} on ${target_file}"
  fi
}

compute_nb_threads() {
  # Increase the number of threads if there is more devices or cores than the default value
  [ $# -gt ${nb_threads} ] && nb_threads=$#
  [ ${first_cores_count} -gt ${nb_threads} ] && nb_threads=${first_cores_count}
}

check_scaling_governor() {
  driver=$(LC_ALL=C cpupower frequency-info |grep "driver:" |awk '{print $2}')
  if [ -z "${driver}" ]; then
    hint "Cannot detect processor scaling driver"
    return
  fi
  cpupower frequency-set -g performance >/dev/null 2>&1 || fatal "Cannot set scaling processor governor"
}

check_idle_governor() {
  filename="/sys/devices/system/cpu/cpuidle/current_governor"
  if [ ! -f "${filename}" ]; then
    hint "Cannot detect cpu idle governor"
    return
  fi
  echo "menu" > ${filename} 2>/dev/null || fatal "Cannot set cpu idle governor to menu"
}

show_nvme() {
  device="$1"
  device_name=$(block_dev_name $1)
  device_dir="/sys/block/${device_name}/device/"
  pci_addr=$(cat ${device_dir}/address)
  pci_dir="/sys/bus/pci/devices/${pci_addr}/"
  link_speed=$(cat ${pci_dir}/current_link_speed)
  irq=$(cat ${pci_dir}/irq)
  numa=$([ -f ${pci_dir}/numa_node ] && cat ${pci_dir}/numa_node || echo "off")
  cpus=$(cat ${pci_dir}/local_cpulist)
  model=$(cat ${device_dir}/model | xargs) #xargs for trimming spaces
  fw=$(cat ${device_dir}/firmware_rev | xargs) #xargs for trimming spaces
  serial=$(cat ${device_dir}/serial | xargs) #xargs for trimming spaces
  info ${device_name} "MODEL=${model} FW=${fw} serial=${serial} PCI=${pci_addr}@${link_speed} IRQ=${irq} NUMA=${numa} CPUS=${cpus} "
  command -v nvme > /dev/null
  if [ $? -eq 0 ]; then
    status=""
    NCQA=$(nvme get-feature -H -f 0x7 ${device} 2>&1 |grep NCQA |cut -d ':' -f 2 | xargs)
    [ -n "${NCQA}" ] && status="${status}Completion Queues:${NCQA}, "
    NSQA=$(nvme get-feature -H -f 0x7 ${device} 2>&1 |grep NSQA |cut -d ':' -f 2 | xargs)
    [ -n "${NSQA}" ] && status="${status}Submission Queues:${NSQA}, "
    power_state=$(nvme get-feature -H -f 0x2 ${device} 2>&1 | grep PS |cut -d ":" -f 2 | xargs)
    [ -n "${power_state}" ] && status="${status}PowerState:${power_state}, "
    apste=$(nvme get-feature -H -f 0xc ${device} 2>&1 | grep APSTE |cut -d ":" -f 2 | xargs)
    [ -n "${apste}" ] && status="${status} Autonomous Power State Transition:${apste}, "
    temp=$(nvme smart-log ${device} 2>&1 |grep 'temperature' |cut -d ':' -f 2 |xargs)
    [ -n "${temp}" ] && status="${status}Temp:${temp}"
    info ${device_name} "${status}"
  fi
}

show_device() {
  device_name=$(block_dev_name $1)
  is_nvme $1 && show_nvme $1
}

show_kernel_config_item() {
  config_item="CONFIG_$1"
  config_file="/boot/config-$(uname -r)"
  if [ ! -f "${config_file}" ]; then
    config_file='/proc/config.gz'
    if [ ! -f "${config_file}" ]; then
      return
    fi
  fi
  status=$(zgrep ${config_item}= ${config_file})
  if [ -z "${status}" ]; then
    echo "${config_item}=N"
  else
    echo "${config_item}=$(echo ${status} | cut -d '=' -f 2)"
  fi
}

show_system() {
  CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo | awk '{print substr($0, index($0,$4))}')
  MEMORY_SPEED=$(dmidecode -t 17 -q | grep -m 1 "Configured Memory Speed: [0-9]" | awk '{print substr($0, index($0,$4))}')
  KERNEL=$(uname -r)
  info "system" "CPU: ${CPU_MODEL}"
  info "system" "MEMORY: ${MEMORY_SPEED}"
  info "system" "KERNEL: ${KERNEL}"
  for config_item in BLK_CGROUP BLK_WBT_MQ HZ RETPOLINE PAGE_TABLE_ISOLATION; do
    info "system" "KERNEL: $(show_kernel_config_item ${config_item})"
  done
  info "system" "KERNEL: $(cat /proc/cmdline)"
  info "system" "SElinux: $(getenforce)"
  tsc=$(journalctl -k | grep 'tsc: Refined TSC clocksource calibration:' | awk '{print $11}')
  if [ -n "${tsc}" ]; then
    info "system" "TSC: ${tsc} Mhz"
    tsc=$(echo ${tsc} | tr -d '.')
    [ -n "${latency_cmdline}" ] && latency_cmdline="-t1 -T${tsc}000"
  fi
}

### MAIN
check_args ${args}
check_root
check_binary t/io_uring lscpu grep taskset cpupower awk tr xargs dmidecode
detect_first_core

info "##################################################"
show_system
for drive in ${drives}; do
  check_drive_exists ${drive}
  check_io_scheduler ${drive}
  check_sysblock_value ${drive} "queue/iostats" 0 # Ensure iostats are disabled
  check_sysblock_value ${drive} "queue/nomerges" 2 # Ensure merge are disabled
  check_sysblock_value ${drive} "queue/io_poll" 1 # Ensure io_poll is enabled
  check_sysblock_value ${drive} "queue/wbt_lat_usec" 0 # Disabling wbt lat
  show_device ${drive}
done

check_poll_queue
compute_nb_threads ${drives}
check_scaling_governor
check_idle_governor

info "##################################################"
echo

cmdline="taskset -c ${taskset_cores} t/io_uring -b512 -d128 -c32 -s32 -p1 -F1 -B1 -n${nb_threads} ${latency_cmdline} ${drives}"
info "io_uring" "Running ${cmdline}"
${cmdline}
