//! This module implements a virtual device middleware for smoltcp.
//! It wraps a 'real' device (`Loopback` in our case) and calls `notify_tx` and `notify_rx`
//! for each transmitted packet. Both functions are externally-defined; they are implemented
//! as a part of the JavaScript API.

use smoltcp::phy::{self, Device, DeviceCapabilities};
use smoltcp::time::Instant;
use smoltcp::Result;

extern "C" {
    /// Notifies the JS API about a new outgoing packet.
    /// `packet` is a pointer to the packet contents.
    /// `len` is the size of a packet.
    fn notify_rx(packet: *const u8, len: usize);

    /// Notifies the JS API about a new incoming packet.
    /// `packet` is a pointer to the packet contents.
    /// `len` is the size of a packet.
    fn notify_tx(packet: *const u8, len: usize);
}
pub struct WasmMiddleware<D: for<'a> Device<'a>> {
    inner: D,
}

impl<D: for<'a> Device<'a>> WasmMiddleware<D> {
    pub fn new(inner: D) -> WasmMiddleware<D> {
        Self { inner }
    }

    /// Get a reference to the underlying device.
    ///
    /// Even if the device offers reading through a standard reference, it is inadvisable to
    /// directly read from the device as doing so will circumvent the tracing.
    #[allow(unused)]
    pub fn get_ref(&self) -> &D {
        &self.inner
    }

    /// Get a mutable reference to the underlying device.
    ///
    /// It is inadvisable to directly read from the device as doing so will circumvent the tracing.
    #[allow(unused)]
    pub fn get_mut(&mut self) -> &mut D {
        &mut self.inner
    }

    /// Return the underlying device, consuming the tracer.
    #[allow(unused)]
    pub fn into_inner(self) -> D {
        self.inner
    }
}

impl<'a, D> Device<'a> for WasmMiddleware<D>
where
    D: for<'b> Device<'b>,
{
    type RxToken = RxToken<<D as Device<'a>>::RxToken>;
    type TxToken = TxToken<<D as Device<'a>>::TxToken>;

    fn capabilities(&self) -> DeviceCapabilities {
        self.inner.capabilities()
    }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let &mut Self { ref mut inner } = self;
        inner.receive().map(|(rx_token, tx_token)| {
            let rx = RxToken { token: rx_token };
            let tx = TxToken { token: tx_token };
            (rx, tx)
        })
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        let &mut Self { ref mut inner } = self;
        inner.transmit().map(|tx_token| TxToken { token: tx_token })
    }
}

pub struct RxToken<Rx: phy::RxToken> {
    token: Rx,
}

impl<Rx: phy::RxToken> phy::RxToken for RxToken<Rx> {
    fn consume<R, F>(self, timestamp: Instant, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        let Self { token } = self;
        token.consume(timestamp, |buffer| {
            unsafe {
                notify_rx(buffer.as_ptr(), buffer.len());
            }
            f(buffer)
        })
    }
}

pub struct TxToken<Tx: phy::TxToken> {
    token: Tx,
}

impl<Tx: phy::TxToken> phy::TxToken for TxToken<Tx> {
    fn consume<R, F>(self, timestamp: Instant, len: usize, f: F) -> Result<R>
    where
        F: FnOnce(&mut [u8]) -> Result<R>,
    {
        let Self { token } = self;
        token.consume(timestamp, len, |buffer| {
            let result = f(buffer);
            unsafe {
                notify_tx(buffer.as_ptr(), buffer.len());
            }
            result
        })
    }
}
