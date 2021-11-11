import pandas as pd
import requests
from sys import argv
from json.decoder import JSONDecodeError

# API address
url = 'https://plasticuproject.pythonanywhere.com/nvd-api/v1/'

def search(*args):

    cves = {} 
    dataframe_list = []
    # Prints help/usage info
    if len(args) == 1 or args[1] == '-h' or args[1] == '--help':
        print('''\nSearch CVE records by ID, YEAR and/or KEYWORD. Prints ID and description only.\n
        USAGE:
        ./cve_search.py <CVE-ID>
        ./cve_serach.py <year> (keyword)
        ./cve_search.py all (keyword)
        ./cve_search.py recent (keyword)
        ./cve_search.py modified (keyword)
        ''' + '\n')
        quit()

    # Adds CVE ID and description to cves dictionary from results matching CVE-ID queried
    elif len(args) == 2 and args[1].startswith('cve') or args[1].startswith('CVE'):
        cve = args[1]
        res = requests.get(url + cve)
        cves[res.json()['cve']['CVE_data_meta']['ID']] = [res.json()['cve']['description']['description_data'][0]['value'],
        res.json()['impact']['baseMetricV3']['cvssV3']['confidentialityImpact'],
        res.json()['impact']['baseMetricV3']['cvssV3']['integrityImpact'],
        res.json()['impact']['baseMetricV3']['cvssV3']['availabilityImpact'],
        res.json()['impact']['baseMetricV3']['cvssV3']['baseSeverity'],
        res.json()['impact']['baseMetricV3']['cvssV3']['baseScore'],
        res.json()['impact']['baseMetricV3']['exploitabilityScore'],
        res.json()['impact']['baseMetricV3']['impactScore']]

        df = pd.DataFrame(cves.items(),columns=['CVE_ID',1])
        expand_value = df[1].apply(pd.Series)
        expand_value = expand_value.rename(columns = {0:'Description', 1:'confidentialityImpact',2:'integrityImpact',3:'availabilityImpact',
        4:'baseSeverity', 5:'baseScore', 6:'exploitabilityScore', 7:'impactScore'})
        final_df = pd.concat([df['CVE_ID'],expand_value],axis=1)
        return final_df

    # Adds CVE ID/s and descriptions/s to cves dictionary from results list if CVEs are found matching criteria
    else:
        date = args[1]
        year = 'year/'
        keyword = ' '.join(args[2:])
        if date == 'all' or date == 'recent' or date == 'modified':
            year = date
            date = ''
        res = requests.get(url + year + date + '?keyword=' + keyword)
        
        for i in res.json():
            cves[i['cve']['CVE_data_meta']['ID']] = i['cve']['description']['description_data'][0]['value']
            
    # Prints if no results are found and cves dictionary is empty
    if len(cves) == 0:
        print('No results found.')
        quit()
   
    df = pd.DataFrame(cves.items(),columns=['CVE_ID','Description'])
    
    impact_data = pd.DataFrame(res.json())['impact'].apply(pd.Series).drop(['baseMetricV2'],axis=1)
    
    final_df = pd.concat([df,impact_data],axis=1).dropna()
    
    baseMetricV3 = final_df['baseMetricV3'].apply(pd.Series)
    ciabb = final_df['baseMetricV3'].apply(pd.Series)['cvssV3'].apply(pd.Series).drop(['version','vectorString','attackVector','attackComplexity','privilegesRequired','userInteraction','scope'],axis=1)
    baseMetricV3 = pd.concat([ciabb,baseMetricV3.drop(['cvssV3'],axis=1)],axis=1)
    
    final_df = pd.concat([final_df.drop(['baseMetricV3'],axis=1),baseMetricV3],axis=1)
        
    # Prints number of results
    if len(cves) > 1:
        print('Results found:', str(len(final_df)))
    
    return final_df

# if __name__ == '__main__':

#     # Run search function and catch all errors and exceptions
#     try:
#         df = search(*argv)
#         print(df.sort_values(['baseScore','CVE_ID'],ascending=False))

#     except (KeyError, TypeError):
#         user_in = ' '.join(argv[1:])
#         print('Did not understand your request for: ' + user_in)
#         quit()

#     except JSONDecodeError:
#         print('NETWORK ERROR: Please check your request or try again later.')
#         quit()

#     except KeyboardInterrupt:
#         quit()