#! /bin/bash


echo "    #     #####   #####      #####  #     # #######    #######                                                 "
echo "   # #   #     # #     #    #     # #     # #          #       #    # #####   ####  #####  ##### ###### #####  "
echo "  #   #  #       #          #       #     # #          #        #  #  #    # #    # #    #   #   #      #    # "
echo " #     # #        #####     #       #     # #####      #####     ##   #    # #    # #    #   #   #####  #    # "
echo " ####### #             #    #        #   #  #          #         ##   #####  #    # #####    #   #      #####  "
echo " #     # #     # #     #    #     #   # #   #          #        #  #  #      #    # #   #    #   #      #   #  "
echo " #     #  #####   #####      #####     #    #######    ####### #    # #       ####  #    #   #   ###### #    # "
                                                                                                               
echo ""
echo "The purpose of this script is to export cve data from Red Hat Advanced Cluster Security into a csv file, including all deployments and images"

set -e

if [[ -z "${ACS_ENDPOINT}" ]]; then
  echo >&2 "A URL to access, stored in the environment variable ACS_ENDPOINT, must be set. Use format sub.domain.com, not including https:// nor /v1..."
  exit 1
fi

if [[ -z "${ACS_API_TOKEN}" ]]; then
  echo >&2 "An API Token, stored in the environment variable ACS_API_TOKEN, must be set. It must have read permissions for alerts, deployments, and images."
  exit 1
fi

if [[ -z "$1" ]]; then
  echo >&2 "Please supply a blank (or existing) csv filename as the first argument for the bash script, ie: './export-cves-to--csv.sh output.csv'"
  exit 1
fi

output_file="$1"
echo '"Deployment", "Image", "CVE", "CVSS Score", "Summary", "Component", "Version", "Fixed By", "Layer Index", "Layer Instruction"' > "${output_file}"

function curl_central() {
  curl -sk -H "Authorization: Bearer ${ACS_API_TOKEN}" "https://${ACS_ENDPOINT}/$1"
}

# Collect all alerts
cvss=7

#res="$(curl_central "v1/alerts?query=Policy%3AFixable%20CVSS%20%3E%3D%20${cvss}")"
res="$(curl_central "v1/alerts")"

# Iterate over all deployments and get the full deployment
for deployment_id in $(echo "${res}" | jq -r .alerts[].deployment.id); do
  deployment_res="$(curl_central "v1/deployments/${deployment_id}")"
  if [[ "$(echo "${deployment_res}" | jq -rc .name)" == null ]]; then
   continue;
  fi
  
  if [[ "$(echo "${deployment_res}" | jq '.containers | length')" == "0" ]]; then
   continue;
  fi

  deployment_name="$(echo "${deployment_res}" | jq -rc .name)"
  export deployment_name
    
   # Iterate over all images within the deployment and render the CSV Lines
   for image_id in $(echo "${deployment_res}" | jq -r 'select(.containers != null) | .containers[].image.id'); do
     if [[ "${image_id}" != "" ]]; then
       image_res="$(curl_central "v1/images/${image_id}" | jq -rc)" 
       if [[ "$(echo "${image_res}" | jq -rc .name)" == null ]]; then
        continue;
       fi

       image_name="$(echo "${image_res}" | jq -rc '.name.fullName')"
       export image_name
       
       # Format the CSV correctly
       echo "${image_res}" | jq -r --argjson cvss "$cvss" 'try (.metadata.v1.layers as $layers | .scan.components | sort_by(.layerIndex, .name) | .[]? | . as $component | select(.vulns != null) | .vulns[] | select(.cvss >= $cvss) | select(.fixedBy != null) | [ env.deployment_name, env.image_name, .cve, .cvss, .summary, $component.name, $component.version, .fixedBy, $component.layerIndex, ($layers[$component.layerIndex // 0].instruction + " " +$layers[$component.layerIndex // 0].value)]) | @csv' >> "${output_file}"
     fi
   done
  done
