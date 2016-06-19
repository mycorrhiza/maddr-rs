use Segment;

#[derive(Eq, PartialEq, Debug)]
pub struct MultiAddr {
    segments: Vec<Segment>,
}

impl MultiAddr {
    pub fn new(segments: Vec<Segment>) -> MultiAddr {
        MultiAddr {
            segments: segments,
        }
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }
}
