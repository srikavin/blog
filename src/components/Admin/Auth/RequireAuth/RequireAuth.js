import React from 'react';
import PropTypes from 'prop-types';
import {Auth} from '../../../../data/resource/auth';
import {Redirect} from 'react-router-dom';

class RequireAuth extends React.Component {
    constructor(props) {
        super(props);
        this.state = {};
    }

    render() {
        if (Auth.isLoggedIn()) {
            return null;
        }
        return <Redirect to={{pathname: '/login', state: {from: this.props.from}}}/>
    }
}

RequireAuth.propTypes = {
    from: PropTypes.string.isRequired
};

export default RequireAuth;