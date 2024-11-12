#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <regex.h>
#include <time.h>

// Tcpdump on pfsync parent interface and maybe filtered on host
#define TCPDUMP_CMD "/usr/sbin/tcpdump -qvni vlan10 -s 1600 host 192.168.1.200"

// IPs à ignorer
const char *ignored_ips[] = {
    "192.168.1.2"
};
const int ignored_ips_count = sizeof(ignored_ips) / sizeof(ignored_ips[0]);

// Fonction utilitaire pour vérifier si une IP doit être ignorée
int is_ip_ignored(const char *ip) {
    for (int i = 0; i < ignored_ips_count; i++) {
        if (strcmp(ip, ignored_ips[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// Fonction principale pour exécuter tcpdump en tâche de fond
void run_tcpdump_and_process_output() {
    FILE *fp;
    char line[2048];
    char lastdate[32] = {0};

    // Expression régulière pour capturer les lignes avec PFSYNCv6
    regex_t regex_pfsync;
    regcomp(&regex_pfsync, "^[0-9:.]+ .* PFSYNCv6", REG_EXTENDED);

    // Expression régulière pour capturer les lignes "all" et extraire les champs
    regex_t regex_all;
    regcomp(&regex_all, "^all ([0-9]+) ([0-9.]+:[0-9]+) \\(([^)]+)\\) -> ([0-9.]+:[0-9]+)", REG_EXTENDED);

    // Exécuter tcpdump et lire sa sortie
    if ((fp = popen(TCPDUMP_CMD, "r")) == NULL) {
        syslog(LOG_ERR, "Failed to run tcpdump");
        exit(1);
    }

    // Traitement des lignes en continu
    while (fgets(line, sizeof(line), fp) != NULL) {
        // Suppression du saut de ligne
        line[strcspn(line, "\n")] = '\0';

        // Vérifier si la ligne contient "PFSYNCv6" et mémoriser le timestamp
        if (regexec(&regex_pfsync, line, 0, NULL, 0) == 0) {
            sscanf(line, "%31s", lastdate);  // Récupérer le timestamp
            continue;
        }

        // Traiter les lignes "all" et extraire les informations
        regmatch_t matches[5];
        if (regexec(&regex_all, line, 5, matches, 0) == 0) {
            char proto[4] = {0}, srcPub[32] = {0}, srcLoc[32] = {0}, dest[32] = {0};
            char proto_num[8] = {0};

            // Extraire le numéro de protocole
            snprintf(proto_num, matches[1].rm_eo - matches[1].rm_so + 1, "%s", line + matches[1].rm_so);
            int proto_int = atoi(proto_num);

            // Convertir le protocole en TCP, UDP, etc.
            if (proto_int == 6) {
                strcpy(proto, "TCP");
            } else if (proto_int == 17) {
                strcpy(proto, "UDP");
            } else {
                snprintf(proto, sizeof(proto), "%d", proto_int);  // Numéro de protocole brut pour les autres cas
            }

            // Extraire les autres champs
            snprintf(srcPub, matches[2].rm_eo - matches[2].rm_so + 1, "%s", line + matches[2].rm_so);
            snprintf(srcLoc, matches[3].rm_eo - matches[3].rm_so + 1, "%s", line + matches[3].rm_so);
            snprintf(dest, matches[4].rm_eo - matches[4].rm_so + 1, "%s", line + matches[4].rm_so);

            // Vérifier si l'adresse SrcLoc doit être ignorée
            char srcLoc_ip[16] = {0};
            sscanf(srcLoc, "%15[^:]", srcLoc_ip);
            if (is_ip_ignored(srcLoc_ip)) {
                continue;
            }

            // Envoyer la ligne formatée au syslog
            syslog(LOG_INFO | LOG_LOCAL1, "%s (%s) %s -> %s", proto, srcLoc, srcPub, dest);
        }
    }

    // Libérer la mémoire et fermer les ressources
    regfree(&regex_pfsync);
    regfree(&regex_all);
    pclose(fp);
}

int main() {
    // Démarrer le syslog
    openlog("tcpdump_processor", LOG_PID , LOG_LOCAL1);
    syslog(LOG_INFO, "Starting tcpdump background processor");

    // Détacher le processus en arrière-plan (daemon)
    pid_t pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "Failed to fork");
        exit(1);
    } else if (pid > 0) {
        // Terminer le processus parent
        exit(0);
    }

    // Exécuter le programme principal
    run_tcpdump_and_process_output();

    // Fermer le syslog
    closelog();
    return 0;
}
