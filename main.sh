#!/bin/bash

# Function to display a colourful figlet banner (rainbow lines)
rainbow_figlet() {
    local text="$1"
    local colors=(31 32 33 34 35 36 91 92 93 94 95 96)
    local i=0
    figlet -f small "$text" | while IFS= read -r line; do
        color=${colors[$((i % ${#colors[@]}))]}
        echo -e "\e[1;${color}m$line\e[0m"
        ((i++))
    done
}

while true; do
    clear
    # Display colourful banner
    rainbow_figlet "Onxx-tool"
    echo -e "\e[1;32m=========================================\e[0m"
    echo -e "\e[1;33m1.\e[0m \e[1;36mInstall Tools\e[0m"
    echo -e "\e[1;33m2.\e[0m \e[1;36mView Info (Instagram & YouTube)\e[0m"
    echo -e "\e[1;33m3.\e[0m \e[1;36mExit\e[0m"
    echo -e "\e[1;32m=========================================\e[0m"
    read -p $'\e[1;35mChoose: \e[0m' opt
    case $opt in
        1)
            echo -e "\e[1;32mStarting installation...\e[0m"
            python onxx.py
            read -p $'\e[1;36mPress Enter to continue...\e[0m'
            ;;
        2)
            clear
            echo -e "\e[1;34m╔═════════════════════════════════════╗\e[0m"
            echo -e "\e[1;34m║\e[0m \e[1;33m       INSTAGRAM & YOUTUBE       \e[1;34m║\e[0m"
            echo -e "\e[1;34m╠═════════════════════════════════════╣\e[0m"
            echo -e "\e[1;34m║\e[0m \e[1;32mInstagram:\e[0m \e[1;36m_insrnx_\e[0m                      \e[1;34m║\e[0m"
            echo -e "\e[1;34m║\e[0m \e[1;32mYouTube:  \e[0m \e[1;36monxx-x145\e[0m                      \e[1;34m║\e[0m"
            echo -e "\e[1;34m╚═════════════════════════════════════╝\e[0m"
            read -p $'\e[1;36mPress Enter to continue...\e[0m'
            ;;
        3)
            echo -e "\e[1;31mExiting... Goodbye!\e[0m"
            exit 0
            ;;
        *)
            echo -e "\e[1;31mInvalid option! Please choose 1, 2, or 3.\e[0m"
            sleep 1
            ;;
    esac
done