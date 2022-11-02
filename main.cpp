#include <QCoreApplication>
#include <pcap.h>

using namespace std;

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(errbuf);
    cout<<"Устройство: " << dev;
    cout<<endl<<endl;
    pcap_t *handle;
    const u_char *pktData;

    //struct bpf_program filter; //Скомпилированное выражение для фильтра
    //char filter_app[] = "port 23"; //Выражение для фильтра

    bpf_u_int32 mask; //Сетевая маска интерфейса
    bpf_u_int32 net; // IP адрес интерфейса

    struct pcap_pkthdr *header; //заголовок пакета, кт заполнит pcap
    const u_char *packet;// сам пакет

   pcap_lookupnet(dev, &net, &mask, errbuf); // Возвращает IP адрес и маску сети
   //handle = pcap_open_live(dev, BUFSIZ, true, 0, errbuf); //Откытие интерфейса для перехвата пакетов
   //pcap_compile(handle, &filter, filter_app, 0, net);
   //pcap_setfilter(handle, &filter);

   handle=pcap_open_offline("C:\\Qt\\Qt5.3.0\\Progekt\\Pcap\\untitled\\mix.cap", errbuf);
   cout<<"Введитe количество пакетов, кт нужно посмотреть: "; int n; cin>>n;
  for(int i=0;i<n;i++){
   pcap_next_ex(handle, &header, &pktData);

   cout<<"Полная длина пакета: ";
   printf("[%d]\n", header->len); cout<<'\n';
   cout<<"Временная метка: "<<header->ts.tv_sec<<'\n';
   cout<<"Длина захваченной части пакета: "<<header->caplen<<'\n';
   #define ETHER_ADDR_LEN	6


       struct sniff_ethernet {
           u_char ether_dhost[ETHER_ADDR_LEN];
           u_char ether_shost[ETHER_ADDR_LEN];
           u_short ether_type;
       };


       struct sniff_ip {
           u_char ip_vhl;
           u_char ip_tos;
           u_short ip_len;
           u_short ip_id;
           u_short ip_off;
       #define IP_RF 0x8000
       #define IP_DF 0x4000
       #define IP_MF 0x2000
       #define IP_OFFMASK 0x1fff
           u_char ip_ttl;
           u_char ip_p;
           u_short ip_sum;
           struct in_addr ip_src,ip_dst;
       };
       #define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
       #define IP_V(ip)		(((ip)->ip_vhl) >> 4)

       /* TCP header */
       typedef u_int tcp_seq;

       struct sniff_tcp {
           u_short th_sport;
           u_short th_dport;
           tcp_seq th_seq;
           tcp_seq th_ack;
           u_char th_offx2;
       #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
           u_char th_flags;
       #define TH_FIN 0x01
       #define TH_SYN 0x02
       #define TH_RST 0x04
       #define TH_PUSH 0x08
       #define TH_ACK 0x10
       #define TH_URG 0x20
       #define TH_ECE 0x40
       #define TH_CWR 0x80
       #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
           u_short th_win;		/* window */
           u_short th_sum;		/* checksum */
           u_short th_urp;		/* urgent pointer */
   };
   const struct sniff_ethernet *ethernet;
   const struct sniff_ip *ip;
   const struct sniff_tcp *tcp;
   const u_char *payload;

   int size_ethernet = sizeof(struct sniff_ethernet);
   int size_ip = sizeof(struct sniff_ip);
   int size_tcp = sizeof(struct sniff_tcp);

   ethernet = (struct sniff_ethernet*)(packet);
   ip = (struct sniff_ip*)(packet + size_ethernet);
   tcp = (struct sniff_tcp*)(
       packet + size_ethernet + size_ip
       );
   payload = (
       packet + size_ethernet + size_ip + size_tcp
       );

    cout<<"МАС адрес получателя: "; printf("[%d]\n",ethernet->ether_dhost);

    cout<<"МАС адрес отправителя: "; printf("[%d]\n",ethernet->ether_shost);

    cout<<"Тип ethernet пртокола: "; printf("[%d]\n",ethernet->ether_type);

    cout<<"IP адрес получателя: "; printf("[%d]\n",ip->ip_dst);

    cout<<"Идентификатор получателя: "; printf("[%d]\n", ip->ip_id);

    cout<<"Длина IP заголовка: "; printf("[%d]\n", ip->ip_len);

    cout<<"Приоритет трафика: "; printf("[%d]\n", ip->ip_tos);

    cout<<"Время жизни пакета: "; printf("[%d]\n", ip->ip_ttl);

    cout<<"Номер подтверждения(ACK) в TCP: "; printf("[%d]\n", tcp->th_ack);

    cout<<"Номер порта получателя: "; printf("[%d]\n", tcp->th_dport);

    cout<<"Флаг TCP: "; printf("[%d]\n", tcp->th_flags);

    cout<<"Порядковый номер первого октета данных: "; printf("[%d]\n", tcp->th_seq);

    cout<<"Номер порта отправителя: "; printf("[%d]\n", tcp->th_sport);

    cout<<"Контрольная сумма: "; printf("[%d]\n", tcp->th_sum);

    cout<<"Размер окна: "; printf("[%d]\n", tcp->th_win);
    cout<<endl<<endl;
  }
   pcap_close(handle);

    return 0;
}
