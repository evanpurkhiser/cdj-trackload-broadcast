import React from 'react';
import ReactDom from 'react-dom';
import Websocket from 'react-websocket';
import './overlay.scss'

const LoadedTrack = (props) => {
  if (props.track === undefined) {
    return <div className="loaded-track"></div>;
  }

  const track = props.track

  let artwork = <div className="artwork">
    <img src={track.artwork} />
  </div>;

  if (track.artwork === null) {
    artwork = <div className="artwork empty"></div>
  }

  return <div className="loaded-track">
    {artwork}
    <div className="details">
      <div className="title">{track.title}</div>
      <div className="artist">{track.artist}</div>
      <div className="album">{track.album}</div>
      <div className="release">
        <span className="label">{track.label}</span>
        <span className="catalog-num">{track.release}</span>
      </div>
    </div>
  </div>;
}

class TrackDisplay extends React.Component {
  constructor(props) {
    super(props);
    this.state = {decks: {}};
  }

  trackLoaded(data) {
    const track  = JSON.parse(data);
    const deckID = track['deck_id'];

    const decks = Object.assign({}, this.state.decks, {[deckID]: track});
    this.setState({decks})
  }

  render() {
    return <div className="track-display">
      <Websocket url="ws://localhost:8008" onMessage={this.trackLoaded.bind(this)} />
      <LoadedTrack track={this.state.decks[3]} />
      <LoadedTrack track={this.state.decks[2]} />
    </div>;
  }
}

ReactDom.render(<TrackDisplay/>, document.getElementById('container'))
