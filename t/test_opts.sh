 #!/bin/bash

#
#############################################################################
#
# test_opts.sh
#
# Script for testing all permutations of command-line options
#
# See sampleTest() for how to define your own test
#

#
# set these variables for your test environment:
#
fio_executable=./fio

#
# Demonstration of using this script
# 
function sampleTest() {

    #
    # sample test execution
    #
    # 1) Create each of your command-line groups (each in a separate array)
    # 2) List the names of all your groups in one array
    # 3) Define arguments that are common to all groups (if any)
    # 4) Call execGroupList
    #
    # See getNextCmdLinePermutation() for how the permutation works
    #

    local numjobs=("numjobs=1" "numjobs=8")
    local rw=("rw=write" "rw=randrw")
    local bs=("bs=512" "bs=64K")
    local thread=("" "thread") # groups can have empty members, to test with and without option
    local all=("numjobs" "rw" "bs" "thread")

    local commonArgs="-name=test -ioengine=null -size=500M -group_reporting -runtime=5"

    echo -e "\nHere are the permutations of options:\n"
    printAllPermutations "${all[@]}";
    echo -e "\nHere are options common to all permutations:\n"
    echo -e "${commonArgs}\n"

    read -p "Press enter to start tests..."

    execGroupList "test" "$commonArgs" "${all[@]}"
}

#
# Iterates the next permutation for groups of command-line options
#
# Parameters:
#
# $1        Permutation to generate, 0..n-1, where 'n' is the total
#           number of combinations possible in the groups passed.
# $2        Array containing list of array names, each of which contains
#           a group of command-line options
#
# Return Value:
#
# retVal    Command line string generated
#
# Example:
#
#   ops=("op=read" "op=write")
#   sizes=("size=10MB" "size=20MB" "size=50MB")
#   all=("ops" "sizes")
#
#   getNextCmdLinePermutation {0..6} "${all[@]}";
#
#   Results for each permutation number passed:
#
#   0: "--op=read --size=10MB"
#   1: "--op=write --size=10MB"
#   2: "--op=read --size=20MB"
#   3: "--op=write --size=20MB"
#   4: "--op=read --size=50MB"
#   5: "--op=write --size=50MB"
#   6: "" (invalid permutation #)
#
function getNextCmdLinePermutation() {

    local permutationToGet=$1
    shift
    local allArgGroups=("$@")
    local numArgGroups="${#allArgGroups[@]}"
    local cmdLine=""
    local groupNum n 

    for ((groupNum=0, n=permutationToGet; groupNum<numArgGroups; groupNum++)); do
        local -n groupVals="${allArgGroups[groupNum]}"
        local numItemsInGroup=${#groupVals[@]}
        local itemIndexInGroup=$((n % numItemsInGroup))
        local item="${groupVals[itemIndexInGroup]}"
        if [[ -n $item ]]; then
            cmdLine+="--${item} "
        fi # else this is an empty item, ex: args=("" "numjobs=4")
        n=$((n / numItemsInGroup))
    done
    # n==0 if permutation # specified is invalid/beyond groups
    if ((n == 0)); then retVal="$cmdLine"; else retVal=""; fi
}

#
# Calculates the number of command line permutations for a group
#
# Parameters:
#
# $1        Array containing list of array names, each of which
#           contains a group of command-line options
#
# Return Value:
#
# retVal    Generated command line string
#
function getNumCmdLinePermutations() {
    local allArgGroups=("$@")
    local numArgGroups="${#allArgGroups[@]}"
    local groupNum count
    for ((groupNum=0, count=1; groupNum<numArgGroups; groupNum++)); do
        local -n groupVals="${allArgGroups[groupNum]}"
        if [[ -z ${groupVals[@]} ]]; then
            echo "Error: Command group \"${allArgGroups[groupNum]}\" not defined";
            exit 1
        fi
        count=$((count * ${#groupVals[@]}))
    done
    retVal=$count

}

#
# Executes fio
#
# Parameters:
#
# $1        Arguments
#
# Return Value:
#
# None - exits script on error
#
function execFio() {
    args="$1"
    "${fio_executable}" $args; exitCode=$?
    if [ $exitCode -ne 0 ]; then
        echo "*** FAILED - exit code is ${exitCode} ***";
        echo "Full Args: $args"
        exit $exitCode
    fi
}

#
# Executes all permutations for groups of command line options 
#
# Parameters:
#
# $1    Test description
# $2    Arguments common to all fio invocations
# $3    Array of command-line option groups. See getNextCmdLinePermutation()
#       for format
#
# Return Value:
#
# None - exits script on error
#
function execGroupList() {

    local permutationNumber countArgPermutations permutationArgs
    local testDescription="$1"
    local commonArgs="$2"
    shift 2
    local allArgGroups=("$@")

    getNumCmdLinePermutations "${allArgGroups[@]}"; countArgPermutations=$retVal

    echo
    echo "**** Starting \"${testDescription}\" - ${countArgPermutations} permutations of arguments..."
    echo

    for ((permutationNumber=0; permutationNumber < countArgPermutations; permutationNumber++)); do
        getNextCmdLinePermutation $permutationNumber "${allArgGroups[@]}"; permutationArgs=$retVal;
        echo "** Executing permutation ${permutationNumber}, args: ${permutationArgs}"
        execFio "$commonArgs $permutationArgs"
    done

    echo
    echo "**** Finished \"${testDescription}\" - ${countArgPermutations} permutations of arguments..."
    echo
}

function printAllPermutations() {
    local allArgGroups=("$@")
    local permutationNumber countArgPermutations permutationArgs
    getNumCmdLinePermutations "${allArgGroups[@]}"; countArgPermutations=$retVal
    for ((permutationNumber=0; permutationNumber < countArgPermutations; permutationNumber++)); do
        getNextCmdLinePermutation $permutationNumber "${allArgGroups[@]}"; permutationArgs=$retVal;
        echo "Permutation ${permutationNumber}: ${permutationArgs}"
    done
}

#
# execute tests
#
sampleTest

