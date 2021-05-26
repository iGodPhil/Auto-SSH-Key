#!/bin/bash

#Dieses Skript erstellt auf Wunsch ein neues SSH Schlüsselpaar
#das Passwort wird automatisch im SSH Schlüsselmanager gespeichert
#der Publik Key wird zum Server übertragen
#auf Wunsch wird ein Bash Skript mit Einwahl zum Server erstellt -> Server wird auf Wunsch automatisch geupdatet bei Einwahl

#Schrifteinstellungen
FETT='\033[1m'
ROT='\033[31m'
RESET='\033[00m'

#Formatierung für neuen Absatz einfügen

absatz(){

}

#globale Variablen
betriebssystem=''
pfad=''
username=''
username_server=''
passwort_user=''
passwort_serveruser=''
passwort_sshkey=''
servername=''
ip_adresse=''
abfrage_eingabe=''

#kopiert denn SSH-Schlüssel auf den Server
ssh_copy_id(){
  touch /tmp/.ssh_copy_id
  chmod +x /tmp/.ssh_copy_id
  cat <<-EOF > /tmp/.ssh_copy_id
  #!/usr/bin/expect -f
  #
  # Install RSA SSH KEY with no passphrase
  #

  set timeout 30
  spawn ssh-copy-id -i $HOME/.ssh/${servername}_rsa.pub $username_server@$ip_adresse
  expect {
      "continue" { send "yes\n"; exp_continue }
      "assword:" { send "${passwort_serveruser}\n"; }
  }
  exit 0
  EOF

  ./tmp/.ssh_copy_id
}

#nur per SSH-Schlüssel Login ermöglichen
add_ssh_only_schluessel(){
  echo -e "Wir verbinden uns wieder mit dem Server und passen erneut die sshd_config Datei an."
  ssh $username_server@$ip_adresse -t " echo $passwort_serveruser | sudo -S sed -i "s/.*PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config;\
                                        echo $passwort_serveruser | sudo -S sed -i "s/.*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/" /etc/ssh/sshd_config;\
                                        echo $passwort_serveruser | sudo -S sed -i "s/.*UsePAM.*/UsePAM no/" /etc/ssh/sshd_config;\
                                        exit"
}

add_ssh_keymanager(){
  touch $HOME/add_ssh_keymanager
  chmod +x $HOME/add_ssh_keymanager
  echo "#!/usr/bin/expect -f
  #
  # Install SSH KEY to KEYMANAGER with no passphrase
  #

  spawn ssh-add /$HOME/.ssh/${servername}_rsa
  expect "Enter passphrase for $HOME/.ssh/${servername}_rsa:"
  send "${passwort_sshkey}\n";
  exit 0" > $HOME/add_ssh_keymanager
  ./$HOME/add_ssh_keymanager
}
#erstellt den SSH-Schlüssel, speichert ihn auf dem Server und im SSH-Schlüsselmanager
#passt die Recht der nötigen Verzeichnisse an
add_ssh_schluessel(){
	if [[ "$betriebssystem" =~ (macos|linux) ]]; then
		echo $passwort_user | sudo -S chmod 755 $HOME/.ssh
    echo -e
    echo -e "Wir erstellen jetzt das SSH-Schlüsselpaar..."
		echo -e "${FETT}Wie soll das Passwort für den SSH-Key lauten?${RESET}"
    read -srp "Eingabe: " passwort_sshkey
    echo -e
    ssh-keygen -b 4096 -N $passwort_sshkey -f $HOME/.ssh/${servername}_rsa
    echo -e
    echo -e "Du besitzt bisher folgende SSH-Schlüssel:"
    echo -e
    ls -l $HOME/.ssh/ | grep .pub
    echo -e
    echo -e "Der private Schlüssel wird nun im SSH-Schlüsselmanager gespeichert..."
    echo $passwort_user | sudo -S eval "$(ssh-agent -s)"
    ssh-add $HOME/.ssh/${servername}_rsa
    echo -e
    ssh_copy_id
    echo -e "Wir melden uns jetzt auf dem Server an und passen die sshd_config Datei an, um die SSH-Einwahl am Server abzusichern..."
    ssh $username_server@$ip_adresse -t " echo $passwort_serveruser | sudo -S sed -i "s/.*PubkeyAuthentication.*/PubkeyAuthentication yes/" /etc/ssh/sshd_config;\
                                          echo $passwort_serveruser | sudo -S sed -i "s/.*LoginGraceTime.*/LoginGraceTime 5m/" /etc/ssh/sshd_config;\
                                          echo $passwort_serveruser | sudo -S sed -i "s/.*MaxAuthTries.*/MaxAuthTries 10/" /etc/ssh/sshd_config;\
                                          echo $passwort_serveruser | sudo -S echo " " >> /etc/ssh/sshd_config;\
                                          echo $passwort_serveruser | sudo -S echo "\# Only allow SSH for users member of group ssh-user" >> /etc/ssh/sshd_config;\
                                          echo $passwort_serveruser | sudo -S echo "AllowGroups ssh-user" >> /etc/ssh/sshd_config;\
                                          echo $passwort_serveruser | sudo -S groupadd ssh-user;\
                                          echo $passwort_serveruser | sudo -S usermod -aG ssh-user $username_server;\
                                          exit"
    echo -e "Ab sofort können sich nur noch User auf deinem Server der Gruppe ssh-user anmelden. $username_server wurde automatisch zur Gruppe hinzugefügt."
    echo -e "${FETT}Möchtest du weitere User zur Gruppe ssh-user hinzufügen? (y|n)${RESET}"
    read -rp "Eingabe: " abfrage_eingabe
    while [[ "$abfrage_eingabe" =~ (y|Y|yes|Yes|yEs|yeS|YEs|YES) ]]; do
      read -rp "Username: " eingabe_username
      ssh $username_server@$ip_adresse -t " echo $passwort_serveruser | sudo -S usermod -aG ssh-user $eingabe_username;\
                                            exit"
      echo -e
      echo -e "${FETT}Möchtest du noch weitere User zur Gruppe ssh-user hinzufügen? (y|n)${RESET}"
      read -rp "Eingabe: " abfrage_eingabe
    done
    echo -e "Fertig."
    echo -e
    echo -e "${FETT}Möchtest du dich zukünftig nur noch mit einem öffentlichen Schlüssel anmelden können? (y|n)${RESET}"
    read -rp "Eingabe: " abfrage_eingabe
    if [[ "$abfrage_eingabe" =~ (y|Y|yes|Yes|yEs|yeS|YEs|YES) ]]; then
      add_ssh_only_schluessel
    fi

  elif [[ "$betriebssystem" = 'windows' ]]; then
    echo -e "Das Skript für Windows ist noch nicht fertig."
    sleep 5
	fi
}

#bei login update ermöglichen
add_login_update(){
  ssh $username_server@$ip_adresse -t " echo $passwort_serveruser | sudo -S touch /etc/sudoers.d/$username_server;\
                                        echo $passwort_serveruser | sudo -S echo "$username_server ALL=NOPASSWD:/usr/bin/apt update,/usr/bin/apt full-upgrade -y" >> /etc/sudoers.d/$username_server;\
                                        echo $passwort_serveruser | sudo -S chown root:root /etc/sudoers.d/$username_server;\
                                        echo $passwort_serveruser | sudo -S chmod 0440 /etc/sudoers.d/$username_server;\
                                        exit"
  echo "sudo apt update;\
        sudo apt full-upgrade -y;\
        echo;echo;echo;echo;echo" > $pfad/ssh_${servername}.sh
}

#erstellt auf Wunsch den SSH Schnellzugriff
#updatet das System auf Wunsch bei Einwahl
add_ssh_datei(){
  echo -e
  echo -e "${FETT}Möchtest du einen Schnellzugriff auf deinem Server anlegen? (y|n)${RESET}"
  read -rp "Eingabe: " abfrage_eingabe
  if [[ "$abfrage_eingabe" =~ (y|Y|yes|Yes|yEs|yeS|YEs|YES) ]]; then
    echo -e
    echo -e "${FETT}Wo möchtest du den Schnellzugriff ablegen?${RESET}"
    read -rpt "Gib den kompletten Pfad an: " pfad
    touch $pfad/ssh_${servername}.sh
    chmod a+x $pfad/ssh_${servername}.sh
    echo "ssh $servername@$ip_adresse" > $pfad/ssh_${servername}.sh
    echo -e
    echo "${FETT}Möchtest du dein System bei Einwahl automatisch updaten? (y|n)${RESET}"
    read -rp "Eingabe: "
    if [[ "$abfrage_eingabe" =~ (y|Y|yes|Yes|yEs|yeS|YEs|YES) ]]; then
      add_login_update
    fi
  fi
}

eingabe_basisdaten(){
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
main(){
  echo -e
  echo -e "Das Skript erstellt ein neues SSH-Schlüsselpaar, damit du dichzukünftig ohne Passwort auf deinem Server anmelden kannst."
  echo -e "Das Passwort für den SSH-Schlüssel wird im SSH-Schlüsselmanager gespeichert."
  echo -e "Auf Wunsch wird ein Schnellzugriff auf deinen Server erstellt."
  echo -e "Die Ausgaben des Skripts werden in einem Logfile gespeichert."
  echo -e "${FETT}${ROT}Alle Passwörter die im Klartext angezeigt werden, werden im Logfile zu sehen sein!${RESET}"
  echo -e
  echo -e "Los gehts. Im ersten Schritt benötige ich folgende Daten von dir:"
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
  echo -e "Überprüfe bitte alle Daten bevor es weitergeht:"
  echo -e "IP-Adresse: $ip_adresse"
  echo -e "Servername: $servername"
  echo -e "Username auf dem Server: $username_server"
  echo -e "Betriebssystem: $betriebssystem"
  echo -e "Dein lokaler Username: $username"
  echo -e "${FETT}${ROT}Möchtest du deine Passwörter im Klartext anzeigen lassen? (y|n)${RESET}"
  read -rp "Eingabe: " abfrage_eingabe
  if [[ "$abfrage_eingabe" =~ (y|Y|yes|Yes|yEs|yeS|YEs|YES) ]]; then
    echo -e "Dein lokales Passwort: $passwort_user"
    echo -e "Dein Server Passwort: $passwort_serveruser"
  fi
  echo -e
  echo -e "${FETT}Stimmen deine Eingaben? (y|n)${RESET}"
  read -rp "Eingabe: " abfrage_eingabe

  #Einrichtung der gewünschten Sachen
  if [[ "$abfrage_eingabe" =~ (y|Y|yes|Yes|yEs|yeS|YEs|YES) ]]; then
    add_ssh_schluessel
    add_ssh_datei
  else
    abfrage_eingabe=1
    while (( $abfrage_eingabe )); do
      echo -e "${FETT}Welchen Punkt möchtest du überarbeiten? (1-7 | 0 zum beenden)${RESET}"
      read -rp "Eingabe: " abfrage_eingabe
      if (( $abfrage_eingabe )); then
        eingabe_basis $abfrage_eingabe
      fi
    done
    add_ssh_schluessel
    add_ssh_datei
  fi

  #Ende
  echo -e
  echo -e "Wir sind jetzt fertig. Ab jetzt kannst du dich sicher ohne Passwort auf deinem Server anmelden."
  echo -e "Das Logfile für den Einrichtungsprozess findest du im Ordner deines Skripts."
  echo -e "Ciao..."

  exit 0
}

log(){
  main > /dev/stdout
}

#Aufruf des Programms
log > ssh_einrichtung_$servername_$(date -Is).log
