import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dosp import ip_to_int, int_to_ip, Client
from dosp.protocol import *

text = """
Lorem ipsum dolor sit amet tempor eros rebum aliquyam et sea dolor dolore et id dolor praesent et. Consequat tempor praesent duis kasd diam amet eos wisi. Est ea elit no vero odio diam duo eirmod clita. Blandit sed diam ad ut consectetuer dolor nonummy lorem aliquyam eros stet amet et tempor tempor. Ea invidunt illum justo dolor magna amet sit feugiat amet. Nonumy sit sanctus ipsum. Labore ut consectetuer kasd sea amet no augue. Sadipscing ipsum nonumy nulla duo accusam rebum autem vero. Illum et et consequat facilisis diam est et lorem sit sadipscing gubergren in lorem justo eos nobis ut. Nonumy diam nibh et vel duo ut autem ipsum feugiat. Amet labore dolor consetetur kasd molestie et vero sanctus eirmod et lorem invidunt ut nobis nulla kasd magna. Stet autem diam est hendrerit enim eros dolor eirmod possim consetetur lorem at nam. Et sanctus lorem eirmod invidunt dolore labore autem ullamcorper. Consectetuer sed exerci erat et no sanctus adipiscing takimata voluptua dolor. Labore enim aliquip nonumy takimata diam assum congue. No et invidunt amet accusam lobortis lorem no accusam duo tation dolore. Aliquip iriure clita qui. Luptatum veniam ipsum invidunt at et et erat ea.

Invidunt diam rebum consequat magna dolor. Justo iusto volutpat in nostrud accusam. Dolores ut magna sit consequat gubergren consetetur diam sed praesent quis diam labore sit dolore liber. Nibh diam invidunt sed sadipscing eros eirmod gubergren et sadipscing diam facilisis consetetur stet. In ipsum vel volutpat. Labore voluptua sea vel dolor laoreet nonumy at commodo sed duo zzril dolor et. Elitr soluta volutpat. Eirmod magna ipsum. Odio et consetetur ea et dolore sit dolor. Consetetur duis sit delenit duis clita accusam lorem est clita takimata tempor tempor veniam invidunt sit aliquyam. Sed magna vulputate sit eos elit lorem sanctus sed takimata feugiat tation diam duo. Dolores diam vulputate lobortis sadipscing. Tempor ipsum autem vel diam accusam dolore nulla ipsum et suscipit sadipscing lorem consetetur.

Et eu et liber nonumy et illum facilisis no eos kasd rebum et consetetur. Dolore magna dolor clita exerci cum eos dolores eos nonumy no. Duis sed consectetuer tation gubergren duo vero sea ex et diam sadipscing. Duo et kasd lobortis. Ipsum justo dolore augue rebum rebum qui at wisi. Sed dolor voluptua lorem dolore dolor et ipsum est sed autem elitr in blandit. Et kasd gubergren ipsum est quis erat est ut exerci odio et et est blandit et vel vel. Est nibh sed clita eos amet diam est eirmod dolor vero tempor tation et. Vero nonumy dolore enim labore. Molestie tincidunt cum et hendrerit erat volutpat eirmod eirmod tempor erat et duis.

Et tation nulla quis sit suscipit magna commodo. Facilisi et labore et augue ea quis ut et sanctus rebum sit erat dolor lobortis odio elit at. Ea clita et sea sit nonumy eos lorem. Et qui sit est duis magna elitr no illum feugiat et kasd lobortis duo dolor ut diam est. Est takimata erat feugait. Erat lorem no dolore ea invidunt eum justo et sit consequat. Qui accusam nisl aliquyam. Et ipsum eu sanctus no ullamcorper iriure tation et dolor magna. Eirmod doming aliquyam sed nostrud et eros sed nulla ut elitr nisl nam sanctus invidunt tempor euismod doming.

Elitr clita nihil et velit nobis lorem est sadipscing at duo te eros labore duo ea no. At erat et clita nonummy quod sed exerci at invidunt ut accusam eu qui diam voluptua facilisi est consetetur. Labore stet ut molestie labore elitr stet clita elitr dolor invidunt et at luptatum eu eu.

Eirmod tempor elitr erat. Lorem facilisis ea takimata aliquyam gubergren nihil imperdiet. Facilisis in veniam et dolor voluptua dignissim molestie diam.

Sit sed invidunt sea at aliquyam ut voluptua. Laoreet molestie nisl dolor sadipscing magna sit ut et ea consequat invidunt amet sit amet consetetur dolor tincidunt. Takimata justo no tation luptatum erat invidunt ut nisl voluptua diam no. Possim gubergren et dolor. Dolor elitr at tempor tempor tation dolor dolores sit tempor ea invidunt voluptua. Accumsan illum sadipscing stet erat sadipscing gubergren sed et feugait sed eos invidunt sit sea aliquyam iriure amet no. Ea soluta est. Facer et ipsum invidunt blandit wisi sadipscing consetetur kasd. Et enim kasd in justo illum ipsum accusam eirmod gubergren et accusam et rebum dolore. Ullamcorper at eu volutpat aliquip diam lorem ut lorem kasd nam elitr ipsum dolore sit magna commodo ipsum. Takimata vero in duo feugiat et et rebum est sit nulla accusam ea rebum clita sanctus consectetuer dolor. Invidunt et kasd invidunt duo dolore laoreet. Dolore eu et aliquyam dolore consectetuer nulla autem consetetur diam vel voluptua ut et.

Facer ipsum ut clita vero laoreet. Gubergren eum lobortis et in luptatum no. Sea accusam amet sanctus velit consequat dolore rebum vulputate feugiat sanctus. Qui sed odio magna ipsum wisi in aliquyam. Euismod magna magna dolore gubergren magna lorem nonumy et no est nostrud dolor magna takimata elitr luptatum sit doming. Magna consetetur gubergren et tation et dolore sit facilisi erat nisl sit sed ex amet. Amet no ipsum ut sed consectetuer sanctus. Tempor nonumy no erat facilisis feugait erat dolore consetetur at nibh diam aliquyam. Dolores sit ex ea ea ea accusam eirmod et dolores. Et clita eos et diam gubergren ea consequat sit. Takimata elitr dolor luptatum takimata sit exerci diam.

Consequat sea sea stet. Ipsum sea nonumy sit ea exerci sit dolor erat nonumy exerci duis invidunt ut eirmod. Eos sit eos. Ipsum sea elitr velit et et erat nonumy invidunt ipsum vel et ea sit et et erat lobortis sit.

Rebum at amet ea takimata sed stet dolor tempor et dolor facilisi eos placerat sea imperdiet. Ut wisi esse sed. Dolor ipsum no elitr dolor. Nonumy et clita kasd diam rebum lorem vulputate duo et ea gubergren dolor takimata delenit magna. Sed iriure vero velit duo takimata no vel takimata volutpat accusam sed vel kasd eirmod liber duo erat lorem. Sed esse ipsum amet et dolor eleifend sea et. Vel ullamcorper at. Dolore justo invidunt eirmod sea labore lobortis labore sanctus et voluptua invidunt eos aliquyam nonumy sadipscing et ut stet. Eleifend dolor nulla elitr lorem clita voluptua rebum. Dignissim sit erat diam sed lorem sanctus tempor et dolor volutpat diam rebum lorem commodo vero aliquyam dolore. Option stet erat takimata at nonumy dolores at illum diam duo kasd. Sadipscing no praesent lorem ea blandit erat sed lorem nihil dolor in dolor sadipscing et eirmod duo eu justo. Voluptua option consequat dolor sadipscing et sed ipsum sit nonumy ea. Sanctus sed eros consetetur ut nonumy gubergren ex dolor duo sea sit. Labore praesent clita et ipsum tempor et erat dolor elitr ut tincidunt rebum et autem. Veniam sit eu adipiscing sit ipsum consequat esse nonumy tempor aliquyam ipsum sadipscing. Rebum ipsum est dolores dolor eros.

Amet labore sit justo eos ipsum est at duo iriure ut. Sit clita sit facer veniam blandit dolore sed accumsan accusam sanctus elitr et doming esse delenit. Luptatum consequat ut at et dolores et et vulputate ut. Aliquyam eirmod et et et ipsum ea.

Dolore sed erat veniam sadipscing elitr rebum voluptua et esse rebum invidunt nonumy ut amet et in. Magna diam no aliquyam dolor diam. Sea invidunt labore sed nulla ut aliquyam dolore. At vero sit eirmod et sea takimata. Nobis et sea kasd hendrerit vel sed gubergren ipsum commodo. Accusam dolore stet gubergren ipsum consetetur luptatum at et ex tation. Accusam vero vero eirmod ipsum euismod amet et duo et et. In ut eos eirmod euismod lorem kasd et consetetur soluta accusam elitr dolor gubergren est stet. At kasd dolor ea at lorem tincidunt nulla eirmod amet et elitr erat. Vel sadipscing dolor voluptua est lorem sanctus molestie gubergren rebum takimata. Voluptua clita esse sea ex nostrud duis duo duis et ipsum dolore tempor et rebum. Dolores gubergren dolor assum feugait et tempor hendrerit vero dolore dolore et kasd vulputate magna praesent sed. Aliquam duo sed facer aliquyam accusam. Magna justo et iriure nihil ipsum tincidunt tempor euismod ut takimata amet no sanctus cum et. Diam clita voluptua amet eirmod lorem diam sadipscing rebum dolor duo vero autem erat lorem sanctus elitr no.

Clita et et voluptua tempor elitr dolores et ex magna sanctus at diam accusam dolor eos justo enim velit. Magna aliquyam amet esse et. Autem sanctus dolor tempor ut feugait dolor magna. Velit consetetur nulla amet. Voluptua diam sanctus nonummy. Amet molestie nonumy magna lorem sit lorem diam lorem tempor. Labore vero eirmod vel diam takimata amet nostrud diam dolor duo amet eum facilisis no rebum et clita ullamcorper. Kasd duo aliquam diam odio minim eum praesent accusam enim sanctus ut nam duo ipsum elitr sed commodo. Ex est iusto ut sit consequat eos nobis facilisis ut eirmod erat illum et vero. At stet amet. Lorem hendrerit sit tempor ut sed diam cum sea amet takimata sea sanctus liber sit sea ipsum takimata nonumy. Nonumy autem vero justo sit nonumy.

Tempor consetetur ipsum. Lorem aliquyam kasd invidunt elit kasd sit. Facilisi suscipit amet dignissim dolore stet voluptua elitr magna enim no in et luptatum. Et eos ut dolore eos sit diam labore dolore vero dolores ut et enim clita ipsum sed soluta. Magna eirmod sanctus vero dolor ut justo sed stet iriure cum magna no te amet. Lorem est et voluptua voluptua. Lorem sed eos dolore voluptua justo et iriure dolor. Dignissim ut consetetur stet at ipsum. Vel tincidunt diam nisl ea amet at kasd accusam takimata dolor dolor vero vero ipsum erat eirmod. Et magna justo ut at illum exerci elitr. Magna vulputate rebum amet. Eos consetetur et vel feugiat dolore sea eirmod sea diam sit sadipscing est lorem eos. Dolore magna ipsum suscipit duo sed. Rebum at erat ipsum placerat diam et sit ex sed. Dolor amet elitr ipsum amet. Sanctus stet adipiscing labore et diam dolore dolor voluptua amet. Stet justo vulputate iriure amet nonumy exerci justo sea et tempor. Sit augue aliquam autem nonummy consequat tempor aliquyam et ipsum at dolores justo qui dolor. Erat stet facilisis aliquip diam no ipsum eros praesent lorem lorem lorem diam nonummy euismod amet stet kasd.

Diam magna et sanctus duo duo iriure sed duo sea accusam sanctus sed vero vero. Est rebum clita. Iriure lorem dolores in ipsum dolor stet duo eos invidunt invidunt kasd amet diam. Lorem lorem et voluptua eum sadipscing no kasd et et. Nulla et dolor nonumy no lorem dolor. Diam ut amet sadipscing. Sit doming eirmod justo duo feugait dolor laoreet ex eos nonumy kasd esse dignissim vero. Nonumy facilisis aliquyam et magna kasd invidunt lorem. Nostrud lobortis sea in feugiat. Mazim vel magna gubergren amet dolor et amet duo quod illum. Est sadipscing vero ipsum vero dolores. Et invidunt eos sit at magna augue kasd iusto ut tation justo nulla amet dolor sed eum. Placerat suscipit ut sadipscing sit takimata eu tempor ut qui odio. Zzril nostrud et et erat facilisis luptatum tempor clita. In ea magna sed aliquip dolor ut dolore veniam augue clita lorem takimata justo ea eum autem.
"""

heavy_packet_text = ("%&DL}" + str(text)).encode()
test_packet_num = 1_000_00
packet = Packet(MSG, heavy_packet_text)

with Client(host="127.0.0.1", port=7744) as client:
    print("vIP:", int_to_ip(client.vip_int))
    start = time.time()
    for _ in range(test_packet_num):
        client.send(packet)
    end = time.time()
    client.close()
    print("Time elapsed:", end - start)
    print("Packets sent:", f"{test_packet_num:,}")
    print("Packet size:", packet.size(), "bytes")
    exit(0)
    client.do_c2c_handshake(c2c_vip=client.vip_int - 1)

    client.send(Packet(
        S2C,
        b"Hello client",
        dst_ip=ip_to_int("7.10.0.4")  # send to this client for testing
    ), on_error="ignore")

    while True:
        pkt = client.receive()
        print(pkt, "BRUH")
        if pkt is None or pkt.type == EXIT:
            break
        print()
        client.send(Packet(
            S2C,
            b"",
            dst_ip=ip_to_int("7.10.0.4")  # send to this client for testing
        ), on_error="ignore")
