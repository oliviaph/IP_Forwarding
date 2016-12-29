/*
Olivia Houghton
CS371-001
Programming Assignment 2
4/20/16
*/

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sstream>

using namespace std;

string decform(uint32_t ip)
{
	string first;
	string second;
	string third;
	string fourth;

	int one;
	int two;
	int three;
	int four;

	one = (ip & 0xff000000) >> 24;
	two = (ip & 0x00ff0000) >> 16;
	three = (ip & 0x0000ff00) >> 8;
	four = (ip & 0x000000ff);

	stringstream s1;
	stringstream s2;
	stringstream s3;
	stringstream s4;

	s1 << one;
	s2 << two;
	s3 << three;
	s4 << four;

	s1 >> first;
	s2 >> second;
	s3 >> third;
	s4 >> fourth;

	string str = first + "." + second + "." + third + "." + fourth;
	return str;
}
// Note: Returns the index of the longest match
unsigned int lpmatch(uint32_t destip, vector<uint32_t> prefixes, vector<uint32_t> masks)
{
	int match_num = 0;
	int longest_size = 0;
	for (size_t i = 0; i < prefixes.size(); i++)
	{
		uint32_t masked_ip = destip & masks[i];
		if (masked_ip == prefixes[i])
		{
			int match_size = 0;
			uint32_t mask = masks[i];
			while(mask > 0) // Count the number of bits in the match, equal to the number of set bits in the mask
			{
				mask = mask >> 1; // Have to right shift because inet_addr right aligns
				match_size++;
			}
			if (match_size >= longest_size)
			{
				longest_size = match_size;
				match_num = i;
			}
		}
	}

	return match_num;
}

uint16_t get_checksum(vector<uint16_t> checks)
{
	unsigned short overflow = 0;
	uint32_t sum = 0;
	for (size_t i = 0; i < checks.size(); i++)
	{
		sum += checks[i];
	}
	overflow = (sum & 0xffff0000) >> 16;
	while (overflow > 0)
	{
		sum = (sum & 0x0000ffff);
		sum += overflow;
		overflow = (sum & 0xffff0000) >> 16;
	}

	return ~sum;
}

/* string break_ip(string ip)
{
	string result;
	char one = ' ';
	char two[2];
	two[0] = ' ';
	two[1] = ' ';
	char three[3];
	three[0] = ' ';
	three[1] = ' ';
	three[2] = ' ';
	int j = 0;
	for (size_t i = 0; i < ip.length(); i++)
	{
		if ((ip[i] == '.') || (i == (ip.length() - 1)))
		{
			unsigned char ip_part;
			if (two[1] == ' ')
			{
				ip_part = atoi(&one);
			}
			else if (three[2] == ' ')
			{
				ip_part = atoi(two);
			}
			else
			{
				ip_part = atoi(three);
			}
			result += ip_part;
			one = ' ';
			two[0] = ' ';
			two[1] = ' ';
			three[0] = ' ';
			three[1] = ' ';
			three[2] = ' ';
		}
		else
		{
			if (one == ' ')
			{
				one = ip[i];
				two[0] = ip[i];
				three[0] = ip[i];
			}
			else if (two[1] == ' ')
			{
				two[1] = ip[i];
				three[1] = ip[i];
			}
			else
			{
				three[2] = ip[i];
			}
		}
		
	}

	return result;
} */

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		cout << "Usage: ipforward routing_table.txt ip_packets ip_packets_out" << endl;
	}
	string table_filename = argv[1];
	string packets_filename = argv[2];
	string output_filename = argv[3];

	vector<uint32_t> netid; 
	vector<uint32_t> netmask;
	vector<uint32_t> nexthop;

	int routing_open_success = 1;

	ifstream infile;
	infile.open(table_filename.c_str());
	if (!(infile.good()))
	{
		cout << "Could not open routing table" << endl;
		routing_open_success = 0;
	}
	int count = 0;
	while (infile.good())
	{
		string str;
		infile >> str;
		uint32_t ip;
		ip = inet_addr(str.c_str());
		if (count == 0)
		{
			netid.push_back(ip);
		}
		else if (count == 1)
		{
			netmask.push_back(ip);
		}
		else
		{
			nexthop.push_back(ip);
			count = -1;
		}

		count++;
	}
	infile.close();

	FILE * fp; // For incoming packets 
	FILE * ofp; // For outgoing packets
	fp = fopen(packets_filename.c_str(), "rb");
	ofp = fopen(output_filename.c_str(), "wb");
	if ((fp != NULL) && routing_open_success && (ofp != NULL))
	{
		while (!feof(fp))
		{
			unsigned int checksum_good = 0;
			vector<uint16_t> chunks; //16 bit chunks for checksum
			uint16_t chunk = 0;
			unsigned char bigbuf[32];
			uint8_t ttl = 0;
			uint32_t sourceip;
			uint32_t destip;
			uint16_t checksum;
			uint16_t calculated_checksum;

			fread(&chunk, 2, 1, fp); // We begin taking 16 bit chunks for the checksum
			chunk = ntohs(chunk);
			chunks.push_back(chunk);

			fread(&chunk, 2, 1, fp); // Get the next 16 bits, the datagram length
			chunk = ntohs(chunk);
			chunks.push_back(chunk);

			uint16_t packetlength = chunk;
			packetlength -= 20; // Taking away the header size

			fread(&chunk, 2, 1, fp); // Identifier, not needed
			chunk = ntohs(chunk);
			chunks.push_back(chunk);

			fread(&chunk, 2, 1, fp); // Flags and frag offset, not needed
			chunk = ntohs(chunk);
			chunks.push_back(chunk);

			fread(&chunk, 2, 1, fp); // TTL and upper-layer protocol, only need the first
			chunk = ntohs(chunk);
			chunks.push_back(chunk); // We'll modify this chunk -- number 4 -- later and recalculate checksum

			ttl = (chunk & 0xff00) >> 8;
			ttl--;

			fread(&checksum, 2, 1, fp); // Getting checksum, we don't use it for our checksum for obvious reasons
			checksum = ntohs(checksum);

			fread(&sourceip, 4, 1, fp); // Getting source ip, no need to convert to host byte order
			uint32_t sourceip_host = ntohl(sourceip);
			chunk = (sourceip_host & 0xffff0000) >> 16;
			chunks.push_back(chunk);
			chunk = (sourceip_host & 0x0000ffff);
			chunks.push_back(chunk);

			fread(&destip, 4, 1, fp); // Getting dest ip, same process
			uint32_t destip_host = ntohl(destip);
			chunk = (destip_host & 0xffff0000) >> 16;
			chunks.push_back(chunk);
			chunk = (destip_host & 0x0000ffff);
			chunks.push_back(chunk);

			cout << "Source IP: " << decform(sourceip_host) << endl;
			cout << "Destination IP: " << decform(destip_host) << endl;
			cout << "Total Length: " << packetlength + 20 << endl;

			// Calculating checksum
			calculated_checksum = get_checksum(chunks);
			if (calculated_checksum == checksum)
			{
				checksum_good = 1;
			}

			if ((ttl > 0) && (checksum_good)) // We don't write the packet to output if ttl is 0 or if checksum is bad
			{
				unsigned int match_index = lpmatch(destip, netid, netmask);
				cout << "Next Hop: " << decform(ntohl(nexthop[match_index])) << endl;
				uint16_t newchunk = 0;
				newchunk = ((ttl << 8) | (chunks[4] & 0x000000ff));
				chunks[4] = newchunk;
				checksum = get_checksum(chunks);
				checksum = htons(checksum);
				for (int i = 0; i < 9; i++) // Writing out the header
				{
					if (i == 5)
					{
						fwrite(&checksum, 2, 1, ofp);
					}
					
					chunks[i] = htons(chunks[i]);
					fwrite(&(chunks[i]), 2, 1, ofp);
					
				}
				while (packetlength > 0) // Copying over the data portion of the packet
				{
					uint16_t amount_read;
					if (packetlength > 32)
					{
						amount_read = fread(bigbuf, 1, 32, fp);
						fwrite(bigbuf, 1, 32, ofp);
						packetlength -= amount_read;
					}
					else
					{
						amount_read = fread(bigbuf, 1, packetlength, fp);
						fwrite(bigbuf, 1, packetlength, ofp);
						packetlength -= amount_read;
					}
				}
			}
			else
			{
				if (!(checksum_good))
				{
					cout << "Dropping packet: Checksum incorrect" << endl;
				}
				else
				{
					cout << "Dropping packet: TTL at 0" << endl;
				}
				while (packetlength > 0) // Reading out the data
				{
					if (packetlength > 32)
					{
						packetlength -= fread(bigbuf, 1, 32, fp);
					}
					else
					{
						packetlength -= fread(bigbuf, 1, packetlength, fp);
					}
				}
			}

			char c = getc(fp); // Prodding to see if we've hit eof
			if (!(c == EOF))
			{
				ungetc(c,fp);
				cout << endl;
			}
		}
	}
	else
	{
		if (fp == NULL)
		{
			cout << "Could not open incoming packets file" << endl;
		}
		else if (ofp == NULL)
		{
			cout << "Could not open file for outgoing packets" << endl;
		}
	}
	if (fp != NULL)
	{
		fclose(fp);
	}
	if (ofp != NULL)
	{
		fclose(ofp);
	}
	
	return 0;
}