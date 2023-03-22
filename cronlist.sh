#!/bin/bash

#found on gist.github.com/islander, edited to output in csv format

# System-wide crontab file and cron job directory. Change these for your system.
CRONTAB='/etc/crontab'
ANACRONTAB='/etc/anacrontab'
CRONDIR='/etc/cron.d'

TIMESTAMP=$(date '+%Y%m%d%H%M%S')
CRONOUTFILE=cronlist-$(hostname)-${TIMESTAMP}.csv
ANACRONOUTFILE=anacronlist-$(hostname)-${TIMESTAMP}.csv
PSOUTFILE=pslist-$(hostname)-${TIMESTAMP}.csv

# Given a stream of crontab lines, exclude non-cron job lines, replace
# whitespace characters with a single space, and remove any spaces from the
# beginning of each line.
function clean_cron_lines() {
    while read line ; do
        echo "${line}" |
            egrep --invert-match '^($|\s*#|\s*[[:alnum:]_]+=)' |
            sed --regexp-extended "s/\s+/ /g" |
            sed --regexp-extended "s/^ //"
    done;
}

# Given a stream of cleaned crontab lines, echo any that don't include the
# run-parts command, and for those that do, show each job file in the run-parts
# directory as if it were scheduled explicitly.
function lookup_run_parts() {
    while read line ; do
        match=$(echo "${line}" | egrep -o 'run-parts (-{1,2}\S+ )*\S+')

        if [[ -z "${match}" ]] ; then
            echo "${line}"
        else
            cron_fields=$(echo "${line}" | cut -f1-6 -d' ')
            cron_job_dir=$(echo  "${match}" | awk '{print $NF}')

            if [[ -d "${cron_job_dir}" ]] ; then
                for cron_job_file in "${cron_job_dir}"/* ; do  # */ <not a comment>
                    [[ -f "${cron_job_file}" ]] && echo "${cron_fields} ${cron_job_file}"
                done
            fi
        fi
    done;
}

# sames as lookup_run_parts, but 5 fields, not 6
function lookup_anacron_parts() {
    while read line ; do
        match=$(echo "${line}" | egrep -o 'run-parts (-{1,2}\S+ )*\S+')

        if [[ -z "${match}" ]] ; then
            echo "${line}"
        else
            cron_fields=$(echo "${line}" | cut -f1-5 -d' ')
            cron_job_dir=$(echo  "${match}" | awk '{print $NF}')

            if [[ -d "${cron_job_dir}" ]] ; then
                for cron_job_file in "${cron_job_dir}"/* ; do  # */ <not a comment>
                    [[ -f "${cron_job_file}" ]] && echo "${cron_fields} ${cron_job_file}"
                done
            fi
        fi
    done;
}

# Temporary file for crontab lines.
temp=$(mktemp) || exit 1

# Add all of the jobs from the system-wide crontab file.
cat "${CRONTAB}" | clean_cron_lines | lookup_run_parts >"${temp}"

# Add all of the jobs from the system-wide cron directory.
cat "${CRONDIR}"/* | clean_cron_lines >>"${temp}"  # */ <not a comment>

# Add each user's crontab (if it exists). Insert the user's name between the
# five time fields and the command.
while read user ; do
    crontab -l -u "${user}" 2>/dev/null |
        clean_cron_lines |
        sed --regexp-extended "s/^((\S+ +){5})(.+)$/\1${user} \3/" >>"${temp}"
done < <(cut --fields=1 --delimiter=: /etc/passwd)

# Output the collected crontab lines. Replace the single spaces between the
# fields with tab characters, sort the lines by hour and minute, insert the
# header line, and format the results as a table.
cat "${temp}" | 
    sed --regexp-extended "s/^(\S+) +(\S+) +(\S+) +(\S+) +(\S+) +(\S+) +(.*)$/\1,\2,\3,\4,\5,\6,\7/" |
    sort --numeric-sort --field-separator="," --key=2,1 |
    sed "1i\mi,h,d,m,w,user,command" >> ${CRONOUTFILE}

rm --force "${temp}"

if [ -f "${ANACRONTAB}" ]
then
    echo -e "period,command" > ${ANACRONOUTFILE}
    cat "${ANACRONTAB}" | clean_cron_lines | lookup_anacron_parts |
	    sed --regexp-extended "s/^(\S+) +(\S+) +(\S+) +(\S+) +(\S+) +(.*)$/\1,\6/" >> ${ANACRONOUTFILE}
fi

ps -e -o %U, -o %p, -o %P, -o %C, -o %t, -o %x, -o %a > ${PSOUTFILE}


tar -czf cronlist-out.tar.gz ${CRONOUTFILE} ${ANACRONOUTFILE} ${PSOUTFILE}
rm ${CRONOUTFILE} ${ANACRONOUTFILE} ${PSOUTFILE}
