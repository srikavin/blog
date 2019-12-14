import * as React from 'react';
import PropTypes from 'prop-types';

class ParagraphRenderer extends React.Component {
    defaults = {
        'color': 'black',
        'font-size': '1rem'
    };

    constructor(props) {
        super(props);
        this.state = {};
    }

    render() {
        let settings;
        if (this.props.settings) {
            settings = Object.assign({}, this.defaults, this.props.settings);
        }

        let styles = {
            'color': settings['color'],
            'fontSize': settings['font-size']
        };

        return (
            <span style={styles}>{this.props.children}</span>
        )
    }
}

ParagraphRenderer.propTypes = {
    src: PropTypes.string,
    settings: PropTypes.object
};

export default ParagraphRenderer;