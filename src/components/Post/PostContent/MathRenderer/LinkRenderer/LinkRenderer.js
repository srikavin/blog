import * as React from 'react';
import PropTypes from 'prop-types';

class LinkRenderer extends React.Component {
    defaults = {
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
            'fontSize': settings['font-size']
        };

        return (
            <a style={styles} target={'_blank'} href={this.props.href}>{this.props.children}</a>
        )
    }
}

LinkRenderer.propTypes = {
    src: PropTypes.string,
    settings: PropTypes.object
};

export default LinkRenderer;