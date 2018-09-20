package com.ppu.fmc.local.handler;

import java.io.File;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

/**
 * https://docs.spring.io/spring-data/jpa/docs/1.11.14.RELEASE/reference/html/
 */

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import java.util.concurrent.CompletableFuture;

import javax.persistence.EntityManager;
import javax.persistence.Query;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import com.ppu.fmc.Local2ovoApplication;
import com.ppu.fmc.exception.IpLocationNotFoundException;
import com.ppu.fmc.local.domain.MacAddr;
import com.ppu.fmc.local.domain.MacAddrUrl;
import com.ppu.fmc.local.model.HostIpMap;
import com.ppu.fmc.local.model.HostMacMap;
import com.ppu.fmc.local.model.IpLocation;
import com.ppu.fmc.local.repo.IBlacklistIpRepository;
import com.ppu.fmc.local.repo.IBlacklistMARepository;
import com.ppu.fmc.local.repo.IConnectionLogRepository;
import com.ppu.fmc.local.repo.IMacAddrRepository;
import com.ppu.fmc.local.repo.IMacAddrUrlRepository;
import com.ppu.fmc.ovo.model.RequestClient;
import com.ppu.fmc.ovo.ws.OVOUrlService;
import com.ppu.fmc.util.StringUtils;
import com.ppu.fmc.util.Utils;

@Component
public class LocalToOvo {
	static Logger log = LoggerFactory.getLogger(LocalToOvo.class);

	@Value("${fmc.fetch.rows:5}")
	private int fmcFetchRows;

	@Value("${ovo.ws.batch.rows:20}")
	private int ovoBatchRows;

	@Value("${local.data.ipclientmap}")
	private String ipclientmap;

	@Value("${local.data.url.keep.days:4}")
	private int keepUrlDays;

	@Value("${local.procbackdate.minutes:15}")
	private int backProcessedDateMinutes;
	
	@Value("${ovo.ws.url}")
	private String urlOVO;

	@Autowired
	@Qualifier("fmcEntityManagerFactory")
	EntityManager em;

	@Autowired
	IMacAddrRepository macAddrRepo;

	@Autowired
	IMacAddrUrlRepository macAddrUrlRepo;

	@Autowired
	IConnectionLogRepository connLogRepo;

	@Autowired
	IBlacklistIpRepository blacklistIpRepo;

	@Autowired
	IBlacklistMARepository blacklistMARepo;

	@Autowired
	private OVOUrlService ovoUrlService;

	@SuppressWarnings("rawtypes")
	public static List loadIpLocationCsv(String csvFilename) throws JsonProcessingException, IOException {
		CsvSchema csvSchema = new CsvMapper().typedSchemaFor(IpLocation.class).withHeader();
		List list = new CsvMapper().readerFor(IpLocation.class)
				.with(csvSchema.withColumnSeparator(CsvSchema.DEFAULT_COLUMN_SEPARATOR))
				.readValues(new File(csvFilename)).readAll();

		/*
		 * for (int i = 0; i < list.size(); i++) { IpLocation _obj = (IpLocation)
		 * list.get(i);
		 * 
		 * System.out.println(_obj); }
		 */

		return list;

	}

	public static String getLocation(List<?> list, String ipAddress) throws IpLocationNotFoundException {
		if (StringUtils.isEmpty(ipAddress) || list == null || list.size() < 1)
			return "";

		// diambil
		StringTokenizer token = new StringTokenizer(ipAddress, ".");

		if (token.countTokens() != 4) {
			throw new IllegalArgumentException("IP address must be in the format 'xxx.xxx.xxx.xxx'");
		}

		int dots = 0;
		String byte1 = "";
		String byte2 = "";
		String byte3 = "";
		while (token.hasMoreTokens()) {
			++dots;

			if (dots == 1) {
				byte1 = token.nextToken();
			} else if (dots == 2) {
				byte2 = token.nextToken();
			} else if (dots == 3) {
				byte3 = token.nextToken();
			} else
				break;
		}

		String client3 = byte1 + "." + byte2 + "." + byte3;

		for (int i = 0; i < list.size(); i++) {
			IpLocation _obj = (IpLocation) list.get(i);

			StringTokenizer _token = new StringTokenizer(_obj.getIp(), ".");

			// segmen class A handler
			if (_token.countTokens() == 3) {
				if (_obj.getIp().equals(client3)) {
					return _obj.getLabel();
				}
			} else if (_token.countTokens() == 4) {
				if (_obj.getIp().equals(ipAddress)) {
					return _obj.getLabel();
				}
			}

		}

		throw new IpLocationNotFoundException(ipAddress);
	}

	private void methodA() throws InterruptedException, RestClientException, KeyManagementException, NoSuchAlgorithmException, KeyStoreException, IOException {
		List listIpLocation = null;
		try {
			listIpLocation = loadIpLocationCsv(ipclientmap);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		cleanUpOldData();

		// 1. cek semua macaddress di table MacAddr
		List<MacAddr> allMac = macAddrRepo.findAll();
//		List<MacAddr> allMac = macAddrRepo.findByMacaddr("00:0C:29:C5:32:45");
//		List<MacAddr> allMac = macAddrRepo.findByIpaddrhex("00000000000000000000FFFF0A0A0AE0");

		// 2. tarik semua url yg ada di table connectionlog, simpan ke table MacAddrUrl
		// dan via table macaddurl kirim ke OVO
		for (MacAddr action : allMac) {
			
			// blacklist check
			if (blacklistIpRepo.findOne(action.getIpaddr()) != null) {
				log.warn("BLACKLISTed IP {}", action.getIpaddr());
				continue;
			}

			if (blacklistMARepo.findOne(action.getMacaddr()) != null) {
				log.warn("BLACKLISTed MacAddress {}", action.getMacaddr());
				continue;
			}
			
			// sometimes krn prosesnya lama, bisa2 next macaddr udah ga terdaftar. so need to check again
			if (macAddrRepo.findByMacaddr(action.getMacaddr()).isEmpty()) {
				log.warn("Missing Mac Address {}", action.getMacaddr());
				continue;
			}

			List<Object[]> items = searchAllUrlInFMCFor(action, fmcFetchRows);

			log.info("There are {} urls in connection_log for ip {}, mac {} since {}", items.size(), action.getIpaddr(), action.getMacaddr(), action.getLastprocesseddate());

			List<String> ipAddressesInHexa = new ArrayList<String>();

			// a. first, collect all ipaddress in hexa
			for (int i = 0; i < items.size(); i++) {
				Object[] fields = items.get(i);

				long firstPacketSec = Long.parseLong(String.valueOf(fields[0]));
				String url = String.valueOf(fields[1]);
				String ipAddressInHexa = String.valueOf(fields[2]);
				String ipAddress = StringUtils.fixIPAddress(String.valueOf(fields[3]));

				boolean found = false;

				for (String _s : ipAddressesInHexa) {
					if (_s.equals(ipAddressInHexa)) {
						found = true;
						break;
					}
				}

				if (!found)
					ipAddressesInHexa.add(ipAddressInHexa);
			}

			// dump into macaddrurl
			for (int i = 0; i < items.size(); i++) {
				Object[] fields = items.get(i);

				long firstPacketSec = Long.parseLong(String.valueOf(fields[0]));
				String url = String.valueOf(fields[1]);
				String ipAddressInHexa = String.valueOf(fields[2]);
				String ipAddress = StringUtils.fixIPAddress(String.valueOf(fields[3]));

//				String macAddress 		= "";
				String iplocation = "";

				try {
					iplocation = getLocation(listIpLocation, ipAddress);
				} catch (Exception e) {
					log.error(e.getMessage(), e);
				}

				MacAddrUrl mau;

//				List<MacAddrUrl> findByUrl = macAddrUrlRepo.findByUrlAndIpaddr(url, ipAddress);
				List<MacAddrUrl> findByUrl = macAddrUrlRepo.findByUrlAndIpaddrAndFirstpacketsec(url, ipAddress, firstPacketSec);

				if (findByUrl.isEmpty()) {
					log.debug("new row[{}/{}] = " + StringUtils.objectsToString(fields, ", "), (i + 1), items.size());

					mau = new MacAddrUrl();
					mau.setCreateddate(LocalDateTime.now());
					mau.setFirstpacketsec(firstPacketSec);
//					mau.setLastpacketsec(lastpacketsec);
					mau.setMacaddr(action.getMacaddr());
					mau.setIpaddr(ipAddress);
					mau.setIplocation(iplocation);
					mau.setUrl(url);

					macAddrUrlRepo.save(mau);

				} else {
//					log.debug("exist row[{}/{}] = " + StringUtils.objectsToString(fields, ", "), (i + 1), items.size());

					mau = findByUrl.get(0);

					if (mau.getFirstpacketsec() < firstPacketSec) {
						mau.setFirstpacketsec(firstPacketSec);
						mau.setSentdate(null); // reset

						macAddrUrlRepo.save(mau);
					}

				}
			} // for (int i=

			boolean anyDataToSentToOvo = false;

			while (true) {
				List<MacAddrUrl> findUnsentData = macAddrUrlRepo.findUnsentUrl(action.getMacaddr(), ovoBatchRows);

				if (findUnsentData.isEmpty())
					break;

				log.debug("Sending {} data to {}", findUnsentData.size(), urlOVO);
				CompletableFuture<?>[] array = new CompletableFuture<?>[findUnsentData.size()];

				for (int j = 0; j < findUnsentData.size(); j++) {
					MacAddrUrl _obj = findUnsentData.get(j);

					RequestClient req = new RequestClient();
					req.setIpaddr(_obj.getIpaddr());
					req.setIplocation(_obj.getIplocation());
					req.setMacaddr(_obj.getMacaddr());
					req.setUrl(_obj.getUrl());
					req.setTime(_obj.getFirstpacketsec());

					req.setEventId(Local2ovoApplication.eventIdIncrementer);

					Local2ovoApplication.eventIdIncrementer += 1;

					array[j] = ovoUrlService.sendData(req);

				}

				anyDataToSentToOvo = true;

				// Wait until they are all done
				CompletableFuture.allOf(array).join();

				findUnsentData.forEach(_content -> {
					_content.setSentdate(LocalDateTime.now());
					macAddrUrlRepo.save(_content);
				});

			}

			// TODO update last dikurangi 30 menit
			if (anyDataToSentToOvo) {
				action.setLastprocesseddate(LocalDateTime.now().minusMinutes(backProcessedDateMinutes));
				macAddrRepo.save(action);
			}
		} // for (MacAddr a

	}

	private void cleanUpOldData() {
		// mundur
		long deletePeriodInseconds = Utils.convertToSeconds(LocalDateTime.now().minusDays(keepUrlDays));
		
		List<MacAddrUrl> findOldData = macAddrUrlRepo.findBySentdateIsNotNullAndFirstpacketsecIsLessThanEqual(deletePeriodInseconds);
		
		if (findOldData.size() > 0) {
			log.warn("There are {}/{} urls in table macaddurl are {} days expired. preview[0]={}", findOldData.size(), macAddrUrlRepo.findAll().size(), keepUrlDays, findOldData.get(0));
			Long deletedRows = macAddrUrlRepo.deleteBySentdateIsNotNullAndFirstpacketsecIsLessThanEqual(deletePeriodInseconds);
//			macAddrUrlRepo.deleteInBatch(findOldData);	
			log.warn("{} rows Cleanup from table MacAddrUrl", deletedRows);
		}
	}

	private List<Object[]> searchAllUrlInFMCFor(MacAddr action, int rowCount) {
		List<Object[]> rows = new ArrayList<>();

		if (StringUtils.isEmpty(action.getIpaddrhex()))
			return rows;

//		select a.url, a.first_packet_sec, a.last_packet_sec,hex(a.initiator_ipaddr) from connection_log a where a.url like 'https://kumparan%' order by a.first_packet_sec desc limit 10;

		StringBuffer sb = new StringBuffer(
				"SELECT a.first_packet_sec, a.url, hex(a.initiator_ipaddr), inet6_ntoa(a.initiator_ipaddr) FROM connection_log a");
		sb.append(" WHERE a.url <> ''");
		// sb.append(" WHERE char_length(a.url) <> 0");

		// tinggal diambil dari createddatenya
		sb.append(" AND a.first_packet_sec >= ");

		if (action.getLastprocesseddate() == null)
			sb.append(Utils.convertToSeconds(action.getCreateddate()));
		else
			sb.append(Utils.convertToSeconds(action.getLastprocesseddate()));

//		sb.append(" AND a.first_packet_sec >= ").append(action.getCreateddate().atZone(ZoneId.systemDefault()).toInstant().toEpochMilli() / 1000);
		// sb.append(" AND a.url <> '").append(fromLastUrl).append("'");

		sb.append(" AND hex(a.initiator_ipaddr) = '").append(action.getIpaddrhex()).append("'");

		// sb.append(" ORDER BY a.first_packet_sec LIMIT ").append(rowCount);
		sb.append(" ORDER BY a.first_packet_sec ASC");
		if (rowCount > 0)
			sb.append(" LIMIT ").append(rowCount);

		Query q = em.createNativeQuery(sb.toString());
//		"select a.first_packet_sec, a.url, hex(a.initiator_ipaddr) from connection_log a where char_length(a.url) <> 0 and a.first_packet_sec > 1531987347 and a.url <> 'http://batsavcdn.ksmobile.net/bsi' order by a.first_packet_sec limit 5";

		try {
			List resultList = q.getResultList();

			if (resultList.size() < 1)
				return rows;

//		Object[] author = (Object[]) q.getSingleResult();

			rows.addAll(resultList);

			log.debug("findNextConnectionLogs return {} rows", resultList.size());

		} catch (Exception e) {
			log.error(e.getMessage(), e);
			log.error("Error when ran {} -> {}", sb.toString(), action);
		}

		return rows;
	}

	private List<HostIpMap> findHostIPAddresses(List<String> ipAddrInHexa) {

		List<HostIpMap> rows = new ArrayList<>();

		if (ipAddrInHexa.size() < 1)
			return rows;

		// construct list into csv
		StringBuffer _csv = new StringBuffer("'" + ipAddrInHexa.get(0) + "'");
		for (int i = 1; i < ipAddrInHexa.size(); i++) {
			_csv.append(",'").append(ipAddrInHexa.get(i)).append("'");
		}

		StringBuffer sb = new StringBuffer("SELECT hex(b.host_id), hex(b.ipaddr) FROM rna_host_ip_map b");
		sb.append(" WHERE hex(b.ipaddr) in (").append(_csv.toString()).append(")");

		Query q = em.createNativeQuery(sb.toString());

		try {
			List resultList = q.getResultList();

			if (resultList.size() < 1)
				return rows;

			for (int i = 0; i < resultList.size(); i++) {
				Object[] _fields = (Object[]) resultList.get(i);

				HostIpMap _obj = new HostIpMap();
				_obj.setHostIdInHexa(String.valueOf(_fields[0]));
				_obj.setIpAddressInHexa(String.valueOf(_fields[1]));

				rows.add(_obj);

			}

			log.debug("findHostIPAddresses return {} rows", resultList.size());

		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}

		return rows;

	}

	private List<HostMacMap> findHostMacAddresses(List<HostIpMap> hostIdsInHexa) {

		List<HostMacMap> rows = new ArrayList<>();

		if (hostIdsInHexa.size() < 1)
			return rows;

		// construct list into csv
		StringBuffer _csv = new StringBuffer("'" + hostIdsInHexa.get(0).getHostIdInHexa() + "'");
		for (int i = 1; i < hostIdsInHexa.size(); i++) {
			_csv.append(",'").append(hostIdsInHexa.get(i).getHostIdInHexa()).append("'");
		}

		StringBuffer sb = new StringBuffer("SELECT hex(c.host_id), hex(c.mac_address) FROM rna_host_mac_map c");
		sb.append(" WHERE hex(c.host_id) in (").append(_csv.toString()).append(")");

		Query q = em.createNativeQuery(sb.toString());

		try {
			List resultList = q.getResultList();

			if (resultList.size() < 1)
				return rows;

			for (int i = 0; i < resultList.size(); i++) {
				Object[] _fields = (Object[]) resultList.get(i);

				HostMacMap _obj = new HostMacMap();
				_obj.setHostIdInHexa(String.valueOf(_fields[0]));
				_obj.setMacAddressInHexa(String.valueOf(_fields[1]));

				rows.add(_obj);
			}

			log.debug("findHostMacAddresses return {} rows", resultList.size());

		} catch (Exception e) {
			log.error(e.getMessage(), e);
		}

		return rows;

	}

	public boolean execute() throws Exception {

		log.debug("fmc.fetch.rows :: {}", fmcFetchRows);
		log.debug("ovo.ws.batch.rows :: {}", ovoBatchRows);
		log.debug("local.data.ipclientmap :: {}", ipclientmap);
		log.debug("local.data.url.keep.days :: {}", keepUrlDays);
		log.debug("local.procdate.minutes :: {}", backProcessedDateMinutes);
		log.debug("ovo.ws.url :: {}", urlOVO);

		try {
			methodA();
		} catch (Exception e) {
			throw e;
		}

		return true;
	}

}
