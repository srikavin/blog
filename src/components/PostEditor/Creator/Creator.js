import React from 'react';

import {StyleSheet} from 'aphrodite';
import PostEditor from '../PostEditor';

class Editor extends React.Component {
    constructor(props) {
        super(props);
    }

    render() {
        return (
            <PostEditor type={'create'}/>
        );
    }
}

const styles = StyleSheet.create({});

export default Editor;
