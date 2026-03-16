use anyhow::{Context, Result};
use futures_util::TryStreamExt;
use rupnp::ssdp::SearchTarget;
use rupnp::Device;
use ssdp_client::URN;
use std::time::Duration;

pub struct UPnPPort {
    pub external_ip: Option<String>,
    port: u16,
    device: Device,
    service_urn: URN,
}

impl UPnPPort {
    pub async fn open(port: u16) -> Result<Self> {
        let (device, service_urn) = find_igd_service().await?;

        let service = device
            .find_service(&service_urn)
            .context("IGD service disappeared after discovery")?;

        let local_ip = get_local_ip();
        let args = format!(
            "<NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>{port}</NewExternalPort>\
             <NewProtocol>TCP</NewProtocol>\
             <NewInternalPort>{port}</NewInternalPort>\
             <NewInternalClient>{local_ip}</NewInternalClient>\
             <NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>upnp</NewPortMappingDescription>\
             <NewLeaseDuration>3600</NewLeaseDuration>"
        );

        service
            .action(device.url(), "AddPortMapping", &args)
            .await
            .context("AddPortMapping failed")?;

        let external_ip = service
            .action(device.url(), "GetExternalIPAddress", "")
            .await
            .ok()
            .and_then(|r| r.get("NewExternalIPAddress").cloned());

        Ok(UPnPPort { external_ip, port, device, service_urn })
    }

    pub async fn close(&self) -> Result<()> {
        let service = self
            .device
            .find_service(&self.service_urn)
            .context("service not found")?;

        let args = format!(
            "<NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>{}</NewExternalPort>\
             <NewProtocol>TCP</NewProtocol>",
            self.port
        );

        let _ = service
            .action(self.device.url(), "DeletePortMapping", &args)
            .await;

        Ok(())
    }
}

async fn find_igd_service() -> Result<(Device, URN)> {
    let wan_ip_urn = URN::service("schemas-upnp-org", "WANIPConnection", 1);
    let wan_ppp_urn = URN::service("schemas-upnp-org", "WANPPPConnection", 1);

    let devices = rupnp::discover(&SearchTarget::RootDevice, Duration::from_secs(3), None)
        .await
        .context("UPnP discovery failed")?;

    tokio::pin!(devices);

    while let Some(device) = devices.try_next().await? {
        if let Some(service) = device.find_service(&wan_ip_urn) {
            let urn = service.service_type().clone();
            return Ok((device, urn));
        }
        if let Some(service) = device.find_service(&wan_ppp_urn) {
            let urn = service.service_type().clone();
            return Ok((device, urn));
        }
    }

    anyhow::bail!("No UPnP IGD device found")
}

fn get_local_ip() -> String {
    local_ip_address::local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

pub fn get_local_ips() -> Vec<String> {
    match local_ip_address::list_afinet_netifas() {
        Ok(interfaces) => interfaces
            .into_iter()
            .filter_map(|(_, ip)| {
                if ip.is_loopback() { None } else { Some(ip.to_string()) }
            })
            .collect(),
        Err(_) => local_ip_address::local_ip()
            .map(|ip| vec![ip.to_string()])
            .unwrap_or_default(),
    }
}

pub async fn open_upnp_port(port: u16) -> Result<UPnPPort> {
    UPnPPort::open(port).await
}