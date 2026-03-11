#!/bin/bash

# ==============================================================================
# CDNHUNTER PRO - Advanced CDN Finder & Origin IP Hunter for Termux
# Versión: 2.1 (Corregida)
# ==============================================================================

# --- CONFIGURACIÓN DE COLORES ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# --- FUNCIÓN BANNER (CORREGIDA) ---
banner() {
    clear
    echo -e "${CYAN}"
    echo "  _______  _______  _______  _        _______ "
    echo " (  ____ )(  ___  )(  ____ \( (    /|(  ____ \\"
    echo " | (    )|| (   ) || (    \/|  \  ( || (    \\/"
    echo " | (____)|| |   | || |      |   \ | || |      "
    echo " |  _____)| |   | || |      | (\ \) || |      "
    echo " | (      | |   | || |      | | \   || |      "
    echo " | )      | (___) || (____/\| )  \  || (____/\\"
    echo " |/       (_______)(_______/|/    )_)(_______/"
    echo -e "            ${WHITE}Advanced CDN & Origin IP Finder${NC}"
    echo -e "    ${YELLOW}----------------------------------------${NC}"
    echo ""
}

# --- VERIFICAR DEPENDENCIAS ---
check_deps() {
    local deps=("curl" "jq" "dig" "grep" "awk")
    local missing=0
    
    for cmd in "${deps[@]}"; do
        if ! command -v $cmd &> /dev/null; then
            echo -e "${RED}[!] Falta: $cmd${NC}"
            missing=1
        fi
    done
    
    if [ $missing -eq 1 ]; then
        echo -e "\n${YELLOW}[*] Instalando dependencias faltantes...${NC}"
        pkg update -y && pkg install curl jq dnsutils -y
        echo -e "${GREEN}[+] Dependencias instaladas.${NC}"
        sleep 2
    fi
}

# --- DETECCIÓN DE PROVEEDOR CDN ---
is_cdn_ip() {
    local ip=$1
    
    # Rangos comunes (Simplificados para velocidad)
    if [[ $ip == 104.* ]] || [[ $ip == 172.6* ]] || [[ $ip == 162.158.* ]] || [[ $ip == 173.245.* ]]; then
        echo "Cloudflare"
    elif [[ $ip == 23.* ]] || [[ $ip == 96.* ]] || [[ $ip == 184.* ]] || [[ $ip == 54.* ]]; then
        echo "Akamai / AWS"
    elif [[ $ip == 151.101.* ]]; then
        echo "Fastly"
    elif [[ $ip == 13.107.* ]] || [[ $ip == 40.112.* ]] || [[ $ip == 52.* ]]; then
        echo "Azure / Microsoft"
    elif [[ $ip == 34.* ]] || [[ $ip == 35.* ]] || [[ $ip == 142.* ]]; then
        echo "Google Cloud"
    else
        echo "Desconocido"
    fi
}

# --- MÉTODO 1: DNS DIRECTO ---
method_dns_direct() {
    local domain=$1
    echo -e "\n${BLUE}[1] ${WHITE}Resolución DNS Directa (A Records)${NC}"
    echo -e "${CYAN}----------------------------------------${NC}"
    
    local ips=$(dig +short "$domain" A 2>/dev/null)
    
    if [ -z "$ips" ]; then
        echo -e "${RED}   Sin resultados.${NC}"
        return
    fi

    for ip in $ips; do
        local provider=$(is_cdn_ip "$ip")
        local status="${GREEN}Posible Origen${NC}"
        
        if [ "$provider" != "Desconocido" ]; then
            status="${YELLOW}CDN Detectado: $provider${NC}"
        fi
        
        echo -e "   IP: ${BOLD}$ip${NC} -> $status"
    done
}

# --- MÉTODO 2: CERTIFICATE TRANSPARENCY ---
method_crt_sh() {
    local domain=$1
    echo -e "\n${BLUE}[2] ${WHITE}Búsqueda en Certificados SSL (crt.sh)${NC}"
    echo -e "${CYAN}----------------------------------------${NC}"
    echo -e "${YELLOW}   Buscando subdominios que puedan revelar la IP real...${NC}"

    local json_data
    json_data=$(curl -s --max-time 15 "https://crt.sh/?q=%.$domain&output=json" 2>/dev/null)
    
    if [ -z "$json_data" ] || [[ "$json_data" == *"error"* ]]; then
        echo -e "${RED}   Error al conectar con crt.sh o límite de tasa.${NC}"
        return
    fi

    # Extraer nombres únicos
    local subs
    subs=$(echo "$json_data" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u | grep -v "^$domain$" | head -n 20)
    
    if [ -z "$subs" ]; then
        echo -e "${GREEN}   No se encontraron subdominios relevantes públicos.${NC}"
        return
    fi

    echo -e "${GREEN}   Subdominios encontrados (Analiza los marcados como FUGA):${NC}"
    while IFS= read -r sub; do
        [ -z "$sub" ] && continue
        local sub_ip
        sub_ip=$(dig +short "$sub" A 2>/dev/null | head -n1)
        
        if [ -n "$sub_ip" ]; then
            local provider=$(is_cdn_ip "$sub_ip")
            if [ "$provider" == "Desconocido" ]; then
                echo -e "   ${GREEN}>> $sub${NC} ($sub_ip) ${BOLD}[POSIBLE FUGA]${NC}"
            else
                echo -e "   $sub ($sub_ip) [$provider]"
            fi
        else
            echo -e "   $sub (Sin resolución IP)"
        fi
    done <<< "$subs"
}

# --- MÉTODO 3: REGISTROS MX ---
method_mx_check() {
    local domain=$1
    echo -e "\n${BLUE}[3] ${WHITE}Análisis de Registros MX (Mail Servers)${NC}"
    echo -e "${CYAN}----------------------------------------${NC}"
    
    local mx_records
    mx_records=$(dig +short "$domain" MX 2>/dev/null | awk '{print $2}')
    
    if [ -z "$mx_records" ]; then
        echo -e "${YELLOW}   Sin registros MX encontrados.${NC}"
        return
    fi

    echo -e "${WHITE}   Servidores de correo detectados:${NC}"
    for mx in $mx_records; do
        mx=${mx%.} # Quitar punto final
        local mx_ip
        mx_ip=$(dig +short "$mx" A 2>/dev/null | head -n1)
        
        if [ -n "$mx_ip" ]; then
            local provider=$(is_cdn_ip "$mx_ip")
            if [ "$provider" == "Desconocido" ]; then
                echo -e "   ${GREEN}>> $mx ($mx_ip) [Posible IP Real de Infraestructura]${NC}"
            else
                echo -e "   $mx ($mx_ip) [$provider]"
            fi
        fi
    done
}

# --- MÉTODO 4: HACKERTARGET ---
method_hacker_target() {
    local domain=$1
    echo -e "\n${BLUE}[4] ${WHITE}Historial DNS (HackerTarget API)${NC}"
    echo -e "${CYAN}----------------------------------------${NC}"
    
    local history
    history=$(curl -s --max-time 15 "https://api.hackertarget.com/dnslookup/?q=$domain" 2>/dev/null)
    
    if [ -z "$history" ] || [[ "$history" == *"error"* ]]; then
        echo -e "${YELLOW}   No se pudo obtener historial o la API está ocupada.${NC}"
        return
    fi

    echo -e "${WHITE}   Resultados históricos:${NC}"
    echo "$history" | while IFS= read -r line; do
        if [[ $line =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            local provider=$(is_cdn_ip "$line")
            if [ "$provider" == "Desconocido" ]; then
                echo -e "   ${GREEN}>> $line [Posible Antiguo Origen]${NC}"
            else
                echo -e "   $line [$provider]"
            fi
        else
            echo -e "   $line"
        fi
    done
}

# --- FLUJO PRINCIPAL ---
main() {
    banner
    check_deps

    echo -ne "\n${BOLD}${GREEN}[*] Ingresa el dominio objetivo: ${NC}"
    read target_domain

    # Limpieza del input
    target_domain=$(echo "$target_domain" | sed -e 's|http://||' -e 's|https://||' -e 's|/.*||' -e 's|^www\.||')

    if [ -z "$target_domain" ]; then
        echo -e "${RED}[!] Error: Dominio inválido.${NC}"
        exit 1
    fi

    echo -e "\n${PURPLE}[*] Iniciando análisis avanzado para: ${BOLD}$target_domain${NC}"
    echo -e "${PURPLE}[*] Fecha: $(date)${NC}"
    
    method_dns_direct "$target_domain"
    method_mx_check "$target_domain"
    method_crt_sh "$target_domain"
    method_hacker_target "$target_domain"

    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${GREEN}[+] Análisis completado.${NC}"
    echo -e "${YELLOW}[-] Consejo: Verifica las IPs marcadas como 'FUGA' o 'Desconocido'.${NC}"
    echo -e "${CYAN}========================================${NC}"
}

# Ejecutar script
main
