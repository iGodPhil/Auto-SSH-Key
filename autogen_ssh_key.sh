#!/usr/bin/env bash

#Dieses Skript erstellt auf Wunsch ein neues SSH Schlüsselpaar
#das Passwort wird automatisch im SSH Schlüsselmanager gespeichert
#der Publik Key wird zum Server übertragen
#auf Wunsch wird ein Bash Skript mit Einwahl zum Server erstellt -> Server wird auf Wunsch automatisch geupdatet bei Einwahl

#Schrifteinstellungen
FETT='\033[1m'
ROT='\033[31m'
RESET='\033[00m'

#Formatierung für neuen Absatz einfügen
function absatz(){
  echo -e
  echo -e
  echo -e "${FETT}#############################################################################${RESET}"
  echo -e
  echo -e
}

#Variablen
betriebssystem=''
pfad=''
username=''
username_server=''
passwort_user=''
passwort_serveruser=''
passwort_sshkey=''
pw=''
servername=''
ip_adresse=''
abfrage_eingabe=''
dir=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

##############################################################################################################################

#SSH Funktionen auf dem Client

##############################################################################################################################

#speichert den Fingerprint des Servers auf dem Client
function ssh_fingerprint() {
  expect <<- EOF
    spawn ssh ${username_server}@${ip_adresse} -t 'exit'
    expect {
      "*fingerprint*" {
        send "yes\r";
        exp_continue
      }
      "*assword:*" {
        send "${passwort_serveruser}\r";
        exp_continue
      }
      eof
    }
EOF
}

#kopiert denn SSH-Schlüssel auf den Server und speichert den Fingerprint auf dem Client
function ssh_copy_id(){
  expect <<- EOF
    spawn ssh-copy-id -i $HOME/.ssh/${servername}_rsa.pub ${username_server}@${ip_adresse}
    expect {
      "*assword:*" {
        send "${passwort_serveruser}\r"
        exp_continue
      }
      eof
    }
EOF
  sleep 5
}

#speichert das Passwort des SSH-Schlüssels im SSH-Manager
function add_ssh_keymanager(){

  if [[ "${betriebssystem}" = "macos" ]]; then
    expect <<- EOF
      spawn ssh-add -K ${HOME}/.ssh/${servername}_rsa
      expect {
        "Enter passphrase for*" {
          send "${passwort_sshkey}\r"
          exp_continue
        }
        eof
      }
EOF
  elif [[ "$betriebssystem" = "linux" ]]; then
    expect <<- EOF
      spawn ssh-add ${HOME}/.ssh/${servername}_rsa
      expect {
        "Enter passphrase for*" {
          send "${passwort_sshkey}\r"
          exp_continue
        }
        eof
      }
EOF
  else
    echo "Windows ist noch nicht fertig."
  fi

}

#Zeigt alle geispeicherten SSH-Schlüsselpasswörter des SSH-Managers an
function show_ssh_add_keys(){
  while read -r line; do
      for file in $HOME/.ssh/*.pub; do
          printf "%s %s\n" "$(ssh-keygen -lf "$file" | awk '{$1=""}1')" "$file";
      done | column -t | grep --color=auto "$line" || echo "$line";
  done < <(ssh-add -l | awk '{print $2}')
  sleep 3
}

#erstellt den SSH-Schlüssel, speichert ihn auf dem Server und im SSH-Schlüsselmanager
#passt die Recht der nötigen Verzeichnisse an
function add_ssh_schluessel() {
  if [[ "$betriebssystem" =~ (macos|linux) ]]; then
    absatz
    echo $passwort_user | sudo -S chmod 755 $HOME/.ssh
    echo -e
    echo -e "Wir erstellen jetzt das SSH-Schlüsselpaar..."
    echo -e "${FETT}Wie soll das Passwort für den SSH-Key lauten?${RESET}"
    read -srp "Eingabe: " passwort_sshkey
    echo -e
    echo -e


    ssh-keygen -b 4096 -N $passwort_sshkey -f $HOME/.ssh/${servername}_rsa
    echo -e
    echo -e "Du besitzt bisher folgende SSH-Schlüssel:"
    echo -e
    ls -l $HOME/.ssh/ | grep .pub
    echo -e
    sleep 3

    if [[ "$betriebssystem" = "linux" ]]; then
      echo -e "Um sicher zu gehen, dass alles funktioniert installieren wir das Programm expect aus den Paketquellen"
      echo "$passwort_user" | sudo -S apt update
      echo "$passwort_user" | sudo -S apt install expect -y
    fi
    echo -e "Der private Schlüssel wird nun im SSH-Schlüsselmanager gespeichert..."
    add_ssh_keymanager
    echo -e
    echo -e


    echo -e "Du hast bisher folgende Schlüssel im SSH-Manager gespeichert:"
    echo -e
    show_ssh_add_keys
    echo -e
    sleep 5


    echo -e "Der öffentliche Schlüssel wird jetzt auf den Server kopiert..."
    ssh_fingerprint
    ssh_copy_id

    absatz

    echo -e "Wir melden uns jetzt auf dem Server an und passen die sshd_config Datei an, um die SSH-Einwahl am Server abzusichern..."

    if [[ "${betriebssystem}" =~ (macos|linux) ]]; then
      ssh $username_server@$ip_adresse bash -s <<-EOF
        echo "$passwort_serveruser" | sudo -S cp /etc/ssh/sshd_config /etc/ssh/sshd_config_$(date +\"%d-%m-%y_%H:%M:%S\").bak
        exit
EOF
    else
      echo "Windows ist noch nicht fertig."
    fi

    ssh $username_server@$ip_adresse bash -s <<-EOF
      echo "$passwort_serveruser" | sudo -S sed -i '/.*PubkeyAuthentication.*/c\PubkeyAuthentication yes/' /etc/ssh/sshd_config
      echo "$passwort_serveruser" | sudo -S sed -i '0,/.*PubkeyAuthentication.*/s//PubkeyAuthentication yes/' /etc/ssh/sshd_config
      echo "$passwort_serveruser" | sudo -S sed -i 's/.*LoginGraceTime.*/LoginGraceTime 5m/' /etc/ssh/sshd_config
      echo "$passwort_serveruser" | sudo -S sed -i 's/.*MaxAuthTries.*/MaxAuthTries 10/' /etc/ssh/sshd_config
      echo "$passwort_serveruser" | sudo -S sed -i '/AllowGroups ssh-user/d' /etc/ssh/sshd_config
      echo "$passwort_serveruser" | sudo -S sed -i '/# Only allow SSH for users member of group ssh-user/d' /etc/ssh/sshd_config
      echo "$passwort_serveruser" | sudo -S sed -i '\$s/[[:space:]]//' /etc/ssh/sshd_config
      echo "$passwort_serveruser" | sudo -S sed -i '\$a\ ' /etc/ssh/sshd_config
      echo "$passwort_serveruser" | sudo -S sed -i '\$a\# Only allow SSH for users member of group ssh-user' /etc/ssh/sshd_config
      echo "$passwort_serveruser" | sudo -S sed -i '\$aAllowGroups ssh-user' /etc/ssh/sshd_config
      echo "$passwort_serveruser" | sudo -S groupadd ssh-user
      echo "$passwort_serveruser" | sudo -S usermod -aG ssh-user $username_server
      echo "$passwort_serveruser" | sudo -S service sshd restart
      exit
EOF
    echo -e
    echo -e "Ab sofort können sich nur noch User auf deinem Server der Gruppe ssh-user anmelden. $username_server wurde automatisch zur Gruppe hinzugefügt."
    abfrage_eingabe='y'
    while [[ "$abfrage_eingabe" =~ (y|Y|yes|Yes|yEs|yeS|YEs|yES|YES) ]]; do
      echo -e "${FETT}Möchtest du noch weitere User zur Gruppe ssh-user hinzufügen? (y|n)${RESET}"
      read -rp "Eingabe: " abfrage_eingabe
      if [[ "$abfrage_eingabe" =~ (y|Y|yes|Yes|yEs|yeS|YEs|yES|YES) ]]; then
        read -rp "Username: " eingabe_username
        ssh $username_server@$ip_adresse bash -s <<-EOF
          echo $passwort_serveruser | sudo -S usermod -aG ssh-user $eingabe_username
          exit
EOF
      fi
      echo -e
    done
    echo -e "Fertig."

    echo -e
    echo -e "${FETT}Möchtest du dich zukünftig nur noch mit einem öffentlichen Schlüssel anmelden können? (y|n)${RESET}"
    read -rp "Eingabe: " abfrage_eingabe
    if [[ "$abfrage_eingabe" =~ (y|Y|yes|Yes|yEs|yeS|YEs|yES|YES) ]]; then
      add_only_ssh_key
    fi

  elif [[ "$betriebssystem" = 'windows' ]]; then
    echo -e "Das Skript für Windows ist noch nicht fertig."
    sleep 5
  fi
}

##############################################################################################################################

#SSH Funktionen auf dem Server

##############################################################################################################################

#nur per SSH-Schlüssel Login ermöglichen
function add_only_ssh_key(){
  echo -e "Wir verbinden uns wieder mit dem Server und passen erneut die sshd_config Datei an."

  if [[ "${betriebssystem}" =~ (macos|linux) ]]; then
    ssh $username_server@$ip_adresse bash -s <<-EOF
      echo "$passwort_serveruser" | sudo -S cp /etc/ssh/sshd_config /etc/ssh/sshd_config_$(date +"%d-%m-%y_%H:%M:%S").bak
      exit
EOF
  else
    echo "Windows ist noch nicht fertig."
  fi

  ssh $username_server@$ip_adresse bash -s <<-EOF
    echo "$passwort_serveruser" | sudo -S sed -i '/.*PasswordAuthentication.*/c\PasswordAuthentication no/' /etc/ssh/sshd_config
    echo "$passwort_serveruser" | sudo -S sed -i '/.*ChallengeResponseAuthentication.*/c\ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    echo "$passwort_serveruser" | sudo -S sed -i '/.*UsePAM.*/c\UsePAM no/' /etc/ssh/sshd_config
    echo "$passwort_serveruser" | sudo -S sed -i '0,/.*PasswordAuthentication.*/s//PasswordAuthentication no/' /etc/ssh/sshd_config
    echo "$passwort_serveruser" | sudo -S sed -i '0,/.*ChallengeResponseAuthentication.*/s//ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
    echo "$passwort_serveruser" | sudo -S sed -i '0,/.*UsePAM.*/s//UsePAM no/' /etc/ssh/sshd_config
    echo "$passwort_serveruser" | sudo -S service sshd restart
    exit
EOF
}

##############################################################################################################################

#SSH Zusatzfunktionen auf dem Client

##############################################################################################################################

#bei login Update ermöglichen
function add_serverupdate_login(){
  ssh $username_server@$ip_adresse bash -s <<-EOF
    echo "$passwort_serveruser" | sudo -S touch /etc/sudoers.d/${username_server}_autoupdate
    echo "$passwort_serveruser" | sudo -S echo "${username_server} ALL=NOPASSWD:/usr/bin/apt update,/usr/bin/apt full-upgrade -y" | (sudo su -c 'EDITOR="tee" visudo -f /etc/sudoers.d/${username_server}_autoupdate') > /dev/null
    exit
EOF
}

#liest die beiden Variablen für die Update Datei ein
function var_einlesen() {
  pw=$(echo "${passwort_serveruser}" | base64)

  server_schnelleinwahl=$(echo "#!/usr/bin/env bash
  eval \$(ssh-agent -s)

  PW='${pw}'
  PW=\$(echo \"\${PW}\" | base64 -d)

  expect <<- EOF
    spawn ssh-add \$HOME/.ssh/${servername}_rsa
    expect {
      \"Enter passphrase for*\" {
        send \"\${PW}\r\"
        exp_continue
      }
      eof
    }
EOF

  ssh ${username_server}@${ip_adresse}

  exit 0")

  server_updateschnelleinwahl=$(echo "#!/usr/bin/env bash
  eval \$(ssh-agent -s)

  PW='${pw}'
  PW=\$(echo \"\${PW}\" | base64 -d)

  expect <<- EOF
    spawn ssh-add \$HOME/.ssh/${servername}_rsa
    expect {
      \"Enter passphrase for*\" {
        send \"\${PW}\r\"
        exp_continue
      }
      eof
    }
EOF

  ssh ${username_server}@${ip_adresse} bash -s <<-EOF
    echo;echo;echo;echo;echo
    echo \"Wir führen jetzt das Update durch...\"; echo ; sudo apt update 2>/dev/null
    echo;echo;echo;echo;echo
    echo \"Wir führen jetzt das Upgrade durch...\"; echo ; sudo apt full-upgrade -y 2>/dev/null
    echo;echo;echo;echo;echo
    exit
EOF

  ssh ${username_server}@${ip_adresse}

  exit 0")
}
#erstellt auf Wunsch den SSH Schnellzugriff
#updatet das System auf Wunsch bei Einwahl
function add_ssh_datei(){
  echo -e
  echo -e
  echo -e "${FETT}Möchtest du einen Schnellzugriff für deinen Server anlegen? (y|n)${RESET}"
  read -rp "Eingabe: " abfrage_eingabe
  if [[ "${abfrage_eingabe}" =~ (y|Y|yes|Yes|yEs|yeS|YEs|yES|YES) ]]; then
    echo -e
    echo -e "${FETT}Wo möchtest du den Schnellzugriff ablegen?${RESET}"
    read -rp "Gib den kompletten Pfad an: " pfad
    var_einlesen
    touch ${pfad}/ssh_${servername}.sh
    echo "$passwort_user" | sudo -S chmod 766 ${pfad}/ssh_${servername}.sh
    echo "${server_schnelleinwahl}" > ${pfad}/ssh_${servername}.sh
    echo -e
    echo -e "${FETT}Möchtest du deinen Server bei Einwahl automatisch updaten? (y|n)${RESET}"
    read -rp "Eingabe: "
    if [[ "${abfrage_eingabe}" =~ (y|Y|yes|Yes|yEs|yeS|YEs|yES|YES) ]]; then
      add_serverupdate_login
      echo "${server_updateschnelleinwahl}" > ${pfad}/ssh_${servername}.sh
    fi
    echo "$passwort_user" | sudo -S sed -i '' 's/^[[:space:]]//g' ${pfad}/ssh_${servername}.sh
    echo "$passwort_user" | sudo -S sed -i '' 's/^[[:space:]]//g' ${pfad}/ssh_${servername}.sh
    echo "$passwort_user" | sudo -S chmod 700 ${pfad}/ssh_${servername}.sh
  fi
}

##############################################################################################################################

#Hauptprogramm

##############################################################################################################################

function eingabe_basisdaten(){
  case "$*" in
    1)  read -rp "1. IP Adresse des Servers: " ip_adresse ;;
    2)  read -rp "2. Name des Servers: " servername ;;
    3)  read -rp "3. Username auf dem Server: " username_server ;;
    4)  read -srp "4. Passwort des Users auf dem Server: " passwort_serveruser ; echo -e ;;
    5)  read -rp "5. Dein Betriebssystem [macos/linux/windows]: " betriebssystem ;;
    6)  read -rp "6. Username auf deinem Betriebssystem: " username ;;
    7)  read -srp "7. Passwort des Users auf deinem Betriebssystem: " passwort_user ; echo -e ;;
  esac
}

#Hauptprogramm
function main(){
  absatz
  echo -e "Das Skript erstellt ein neues SSH-Schlüsselpaar, damit du dich zukünftig ohne Passwort auf deinem Server anmelden kannst."
  echo -e "Das Passwort für den SSH-Schlüssel wird im SSH-Schlüsselmanager gespeichert."
  echo -e "Auf Wunsch wird ein Schnellzugriff auf deinen Server erstellt."
  echo -e
  echo -e "${FETT}${ROT}Dein User auf dem Server muss der Gruppe sudo angehören!${RESET}"
  echo -e
  echo -e "Kann es losgehen? (y|n)"
  read -rp "Eingabe: " abfrage_eingabe
  if [[ "${abfrage_eingabe}" =~  (y|Y|yes|Yes|yEs|yeS|YEs|yES|YES) ]]; then
    continue > /dev/null 2>&1
  else
    echo -e "Ciao bis zum nächsten Mal..."
    exit 0
  fi
  echo -e
  echo -e "Dann geht's jetzt los. Im ersten Schritt benötige ich folgende Daten von dir:"
  echo -e


  #Ruft zu Begin alle Eingabeparameter auf
  for (( i = 1; i < 8; i++ )); do
    eingabe_basisdaten $i
  done
  echo -e

  #Überprüfung der Syntax der Eingaben
  while [ -z "$ip_adresse" ]; do
  	echo -e
  	echo "Die IP-Adresse darf nicht leer bleiben."
  	read -rp "IP Adresse des Servers: " ip_adresse
  done

  while [ -z "$servername" ]; do
  	echo -e
  	echo "Der Name des Servers darf nicht leer bleiben."
  	read -rp "Name des Servers: " servername
  done

  while [ -z "$username_server" ]; do
  	echo -e
  	echo "Der Username auf dem Server darf nicht leer bleiben."
  	read -rp "Username auf dem Server: " username_server
  done

  while ! [[ "$betriebssystem" =~ (macos|linux|windows) ]]; do
  	echo -e
  	echo "Bitte gib ein passendes Betriebssystem ein!"
  	read -rp "Dein Betriebssystem [macos/linux/windows]: " betriebssystem
  done

  while [ -z "$username" ]; do
  	echo -e
  	echo "Der Username darf nicht leer bleiben."
  	read -rp "Username auf deinem Betriebssystem: " username
  done

  #Überprüfung ob der User alle Daten richtig eingegeben hat
  echo -e
  echo -e "${FETT}Überprüfe bitte alle Daten bevor es weitergeht:${RESET}"
  echo -e "IP-Adresse: $ip_adresse"
  echo -e "Servername: $servername"
  echo -e "Username auf dem Server: $username_server"
  echo -e "Betriebssystem: $betriebssystem"
  echo -e "Dein lokaler Username: $username"
  echo -e
  echo -e "${FETT}${ROT}Möchtest du deine Passwörter im Klartext anzeigen lassen? (y|n)${RESET}"
  read -rp "Eingabe: " abfrage_eingabe
  if [[ "$abfrage_eingabe" =~ (y|Y|yes|Yes|yEs|yeS|YEs|yES|YES) ]]; then
    echo -e
    echo -e "Dein lokales Passwort: $passwort_user"
    echo -e "Dein Server Passwort: $passwort_serveruser"
  fi
  echo -e
  echo -e "${FETT}Stimmen deine Eingaben? (y|n)${RESET}"
  read -rp "Eingabe: " abfrage_eingabe

  #Einrichtung der gewünschten Sachen
  if [[ "$abfrage_eingabe" =~ (y|Y|yes|Yes|yEs|yeS|YEs|yES|YES) ]]; then
    add_ssh_schluessel
    add_ssh_datei
  else
    abfrage_eingabe=1
    while (( ${abfrage_eingabe} )); do
      echo -e "${FETT}Welchen Punkt möchtest du überarbeiten? (1-7 | 0 zum beenden)${RESET}"
      read -rp "Eingabe: " abfrage_eingabe
      if (( ${abfrage_eingabe} )); then
        eingabe_basisdaten ${abfrage_eingabe}
      fi
    done
    add_ssh_schluessel
    add_ssh_datei
  fi

  #Ende
  echo -e
  echo -e
  echo -e "Wir sind jetzt fertig. Ab jetzt kannst du dich sicher ohne Passwort auf deinem Server anmelden."
  echo -e "Ciao..."

  exit 0
}

#Aufruf des Programms
main
