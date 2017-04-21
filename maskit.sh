#!/bin/bash

# date 2017-01-23 

proxy_user=admin
proxy_pwd=admin
proxy_port=6032
proxy_host=127.0.0.1

contact="dba@acme.com"

username=devel

which mysqladmin >/dev/null 2>&1
if [ $? -ne 0 ]
then
  echo "mysql client is not found in path, please install..."
  exit 2
fi


if [ $# -eq 0 ]
then
  echo "$0 requires options:" 
  echo "                     -c to specify a column," 
  echo "                     -d to specify the schema"
  echo "                     -o to specify obfuscation format"
  echo "                         example -o '9999-99-99' or 'XXXXX'"
  echo "                     -t to specify a table where select * is not allowed"
  exit 1
fi

while getopts ":d:c:o:t:" opt
do
  case $opt in
   c)
      echo "column: $OPTARG"
      COLUMN=$OPTARG
      ;;
   d)
      echo "schema: $OPTARG"
      DATABASE=$OPTARG
      ;;
   o)
      echo "obfuscation required using format : $OPTARG"
      FORMAT=$OPTARG
      echo $FORMAT | grep -v "^[9X _-]*$" >/dev/null
      if [ $? -eq 0 ]
      then
        echo "ERROR: output format not allowed, only 9, X, -, _ and space are supported!"
        exit 1
      fi 
      IFS=' |-|_' read -ra array_1 <<< "$FORMAT"
      FORMAT_OUT="CONCAT("
      len_i=0
      for i in "${array_1[@]}"
      do
        if [ "$i" -eq "$i" ] 2>/dev/null
        then
          # we are in numeric
          start=2
          end=${#i}
          st1="1"       
          for ((j=$start; j<=$end; j++))
          do
            st1=$st1"0"
          done
          st2=$(( $st1 * 5 ))
          len_i=$(( $len_i + ${#i} ))
          FORMAT_OUT="$FORMAT_OUT floor(rand() % $st2) + $st1,'${FORMAT:$len_i:1}'," 
          len_i=$(( $len_i + 1 ))
        fi
      done
      FORMAT_OUT="${FORMAT_OUT::-1})"
      echo $FORMAT_OUT
      ;;
   t) 
      echo "table: $OPTARG"
      TABLE=$OPTARG
      ;;
   \?)
      echo "Invalid option: -$OPTARG"
      exit 1
      ;;
   :)
      echo "Option -$OPTARG requires an argument."
      exit 1
      ;;
   esac
done


#check the column rules
if [ "$COLUMN" != "" ]
then
  # we don't perform check (yet) so watchout for duplicates
  mysql -BN -u ${proxy_user} -p${proxy_pwd} -h ${proxy_host} -P${proxy_port} \
  -e "INSERT INTO mysql_query_rules 
      (active,schemaname,username,match_pattern,replace_pattern,apply,re_modifiers)  
      VALUES 
      (1,'${DATABASE}','${username}','\`*${COLUMN}*\`','${COLUMN}',0,'caseless,global');"
  if [ ${#FORMAT_OUT} -gt 0 ]
  then
  	mysql -BN -u ${proxy_user} -p${proxy_pwd} -h ${proxy_host} -P${proxy_port} \
  	-e "INSERT INTO mysql_query_rules 
        (active,schemaname,username,match_pattern,replace_pattern,apply,re_modifiers)  
        VALUES 
        (1,'${DATABASE}','${username}','(\(?)(\`?\w+\`?\.)?${COLUMN}(\)?)([ ,\n])',\"\1${FORMAT_OUT//\%/*}\3 ${COLUMN}\4\",0,'caseless,global');"
  else
  	mysql -BN -u ${proxy_user} -p${proxy_pwd} -h ${proxy_host} -P${proxy_port} \
  	-e "INSERT INTO mysql_query_rules 
        (active,schemaname,username,match_pattern,replace_pattern,apply,re_modifiers)  
        VALUES 
        (1,'${DATABASE}','${username}','(\(?)(\`?\w+\`?\.)?${COLUMN}(\)?)([ ,\n])',\"\1CONCAT(LEFT(\2${COLUMN},2),REPEAT('X',10))\3 ${COLUMN}\4\",0,'caseless,global');"
  fi
  mysql -BN -u ${proxy_user} -p${proxy_pwd} -h ${proxy_host} -P${proxy_port} \
  -e "INSERT INTO mysql_query_rules 
      (active,schemaname,username,match_pattern,replace_pattern,apply,re_modifiers)  
      VALUES 
      (1,'${DATABASE}','${username}','\)(\)?) ${COLUMN}\s+(\w),',')\1 \2,',1,'caseless,global'),
      (1,'${DATABASE}','${username}','\)(\)?) ${COLUMN}\s+(.*)\s+from',')\1 \2 from',1,'caseless,global');"
  
fi

# check if we need to add a rule to avoid select * in a table
if [ "$TABLE" != "" ]
then
   # connect to proxysql and check is a rule already exists
   echo $(mysql -BN -u ${proxy_user} -p${proxy_pwd} -h ${proxy_host} -P${proxy_port} \
   -e "select rule_id,active from mysql_query_rules where match_pattern like '^SELECT \*.*FROM.*${TABLE}';" 2>/dev/null) | while read rule_id active
   do
      if [ "$rule_id" != "" ]
      then
         echo -n "there is already a rule : rule_id = $rule_id "
         if [ "$active" == "1" ]  
         then
           echo "[active]"
         else
           echo "[inactive]"
           # we need to activate it
           mysql -BN -u ${proxy_user} -p${proxy_pwd} -h ${proxy_host} -P${proxy_port} \
           -e "update mysql_query_rules set active=1 where rule_id=$rule_id"
         fi
      else
         echo "let's add the rules..."
         mysql -BN -u ${proxy_user} -p${proxy_pwd} -h ${proxy_host} -P${proxy_port} \
           -e "INSERT INTO mysql_query_rules (active,schemaname,username,match_pattern,error_msg,re_modifiers)
               VALUES (1,'${DATABASE}','${username}','^SELECT\s+\*.*FROM.*${TABLE}', 
               'Query not allowed due to sensitive information, please contact ${contact}','caseless,global' );"
         mysql -BN -u ${proxy_user} -p${proxy_pwd} -h ${proxy_host} -P${proxy_port} \
           -e "INSERT INTO mysql_query_rules (active,schemaname,username,match_pattern,error_msg,re_modifiers)
               VALUES (1,'${DATABASE}','${username}','^SELECT\s+${TABLE}\.\*.*FROM.*${TABLE}', 
               'Query not allowed due to sensitive information, please contact ${contact}','caseless,global' );"
         mysql -BN -u ${proxy_user} -p${proxy_pwd} -h ${proxy_host} -P${proxy_port} \
           -e "INSERT INTO mysql_query_rules (active,schemaname,username,match_pattern,error_msg,re_modifiers)
               VALUES (1,'${DATABASE}','${username}','^SELECT\s+(\w+)\.\*.*FROM.*${TABLE}\s+(as\s+)?(\1)', 
               'Query not allowed due to sensitive information, please contact ${contact}','caseless,global' );"
      fi 
   done
fi

mysql -BN -u ${proxy_user} -p${proxy_pwd} -h ${proxy_host} -P${proxy_port} \
-e "set mysql-query_processor_regex=1; load mysql variables to runtime; load mysql query rules to runtime;"
